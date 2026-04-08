//! Flat block file storage — `blk*.dat` and `rev*.dat`.
//!
//! # Layout (mirrors Bitcoin Core exactly)
//!
//! ```text
//! blocks/
//!   blk00000.dat   ← raw blocks, network format, append-only
//!   blk00001.dat
//!   ...
//!   rev00000.dat   ← undo data for blocks in the corresponding blk file
//!   rev00001.dat
//!   ...
//! ```
//!
//! # Record format (both blk and rev)
//!
//! ```text
//! [ magic (4 bytes) ][ size (4 bytes LE) ][ data (size bytes) ]
//! ```
//!
//! # File lifecycle
//!
//! 1. Space is pre-allocated in chunks to reduce filesystem fragmentation.
//! 2. When a blk file reaches `MAX_BLOCK_FILE_SIZE`, the manager rotates to
//!    the next file number.
//! 3. When a file is complete, it is "finalized": the unused pre-allocated
//!    tail is truncated and the file is synced.
//! 4. Blocks arrive out of order during IBD and are written as received.
//!    Undo data is written only when a block is connected to the chain tip.
//! 5. Every block's `FlatFilePos` is stored in the block index so it can be
//!    retrieved by hash without scanning.

use crate::error::StoreError;
use bitcrab_common::wire::{
    decode::{BitcoinDecode, Decoder},
    encode::{BitcoinEncode, Encoder},
    error::DecodeError,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
};

// ── Constants ─────────────────────────────────────────────────────────────────

use bitcrab_common::constants::{BLOCK_FILE_CHUNK, MAX_BLOCK_FILE_SIZE, UNDO_FILE_CHUNK};

// ── Magic ─────────────────────────────────────────────────────────────────────

/// Network-specific message start bytes prepended to every record.
///
/// Bitcoin Core: `CChainParams::MessageStart()`
pub use bitcrab_common::Magic;

pub use bitcrab_common::FlatFilePos;

// ── BlockFileInfo ─────────────────────────────────────────────────────────────

/// Metadata about a single `blk*.dat` / `rev*.dat` file pair.
///
/// Equivalent to Bitcoin Core's `CBlockFileInfo`.
/// Persisted in the block index under the `f` + file-number key.
///
/// Serialised as 36 bytes (all fields LE):
/// ```text
/// blocks     (u32)  4 bytes
/// size       (u64)  8 bytes
/// undo_size  (u64)  8 bytes
/// height_first (u32) 4 bytes
/// height_last  (u32) 4 bytes
/// time_first   (u32) 4 bytes
/// time_last    (u32) 4 bytes
///                   --------
///                   36 bytes
/// ```
#[derive(Debug, Clone, Default)]
pub struct BlockFileInfo {
    /// Number of blocks stored in this file.
    pub blocks: u32,
    /// Bytes used in `blk*.dat` (including headers).
    pub size: u64,
    /// Bytes used in `rev*.dat` (including headers).
    pub undo_size: u64,
    /// Lowest block height stored in this file.
    pub height_first: u32,
    /// Highest block height stored in this file.
    pub height_last: u32,
    /// Earliest block timestamp in this file (Unix epoch).
    pub time_first: u32,
    /// Latest block timestamp in this file (Unix epoch).
    pub time_last: u32,
}

impl BlockFileInfo {
    /// Update height and timestamp bounds when a new block is added.
    pub fn update_for_block(&mut self, height: u32, time: u32) {
        if self.blocks == 0 {
            self.height_first = height;
            self.time_first = time;
        }
        self.blocks += 1;
        self.height_last = self.height_last.max(height);
        self.time_last = self.time_last.max(time);
    }
}

impl BitcoinEncode for BlockFileInfo {
    fn encode(&self, enc: Encoder) -> Encoder {
        enc.encode_field(&self.blocks)
            .encode_field(&self.size)
            .encode_field(&self.undo_size)
            .encode_field(&self.height_first)
            .encode_field(&self.height_last)
            .encode_field(&self.time_first)
            .encode_field(&self.time_last)
    }
}

impl BitcoinDecode for BlockFileInfo {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        let (blocks, dec) = dec.decode_field::<u32>("BlockFileInfo::blocks")?;
        let (size, dec) = dec.decode_field::<u64>("BlockFileInfo::size")?;
        let (undo_size, dec) = dec.decode_field::<u64>("BlockFileInfo::undo_size")?;
        let (height_first, dec) = dec.decode_field::<u32>("BlockFileInfo::height_first")?;
        let (height_last, dec) = dec.decode_field::<u32>("BlockFileInfo::height_last")?;
        let (time_first, dec) = dec.decode_field::<u32>("BlockFileInfo::time_first")?;
        let (time_last, dec) = dec.decode_field::<u32>("BlockFileInfo::time_last")?;
        Ok((
            BlockFileInfo {
                blocks,
                size,
                undo_size,
                height_first,
                height_last,
                time_first,
                time_last,
            },
            dec,
        ))
    }
}

// ── FlatFileSeq ───────────────────────────────────────────────────────────────

/// A numbered sequence of flat files sharing a common prefix.
///
/// Manages one family of files (`blk*.dat` or `rev*.dat`):
/// path construction, pre-allocation, finalization.
///
/// Equivalent to Bitcoin Core's `FlatFileSeq`.
#[derive(Debug, Clone)]
pub struct FlatFileSeq {
    dir: PathBuf,
    prefix: &'static str,
    chunk_size: u64,
}

impl FlatFileSeq {
    pub fn new(dir: impl Into<PathBuf>, prefix: &'static str, chunk_size: u64) -> Self {
        Self {
            dir: dir.into(),
            prefix,
            chunk_size,
        }
    }

    /// Build the path for file number `n` — e.g. `blocks/blk00042.dat`.
    pub fn path(&self, n: u32) -> PathBuf {
        self.dir.join(format!("{}{:05}.dat", self.prefix, n))
    }

    /// Open file `n` for appending, creating it if it does not exist.
    /// Pre-allocates space up to the next chunk boundary.
    pub fn open_for_write(&self, n: u32) -> Result<File, StoreError> {
        fs::create_dir_all(&self.dir).map_err(StoreError::Io)?;
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(self.path(n))
            .map_err(StoreError::Io)?;
        self.preallocate(&file)?;
        Ok(file)
    }

    /// Open file `n` read-only.
    pub fn open_for_read(&self, n: u32) -> Result<File, StoreError> {
        File::open(self.path(n))
            .map_err(|_| StoreError::BlockFileUnavailable { file: n, offset: 0 })
    }

    /// Finalize file `n`: truncate unused pre-allocated space and fsync.
    ///
    /// Called once a file is complete and no further appends will occur.
    /// Matches Bitcoin Core's `FlatFileSeq::Flush(pos, finalize=true)`.
    pub fn finalize(&self, n: u32, used_bytes: u64) -> Result<(), StoreError> {
        let file = OpenOptions::new()
            .write(true)
            .open(self.path(n))
            .map_err(StoreError::Io)?;
        file.set_len(used_bytes).map_err(StoreError::Io)?;
        file.sync_all().map_err(StoreError::Io)?;
        Ok(())
    }

    /// Write a single zero byte at the next chunk boundary so the OS
    /// pre-allocates disk space, reducing later fragmentation.
    ///
    /// Matches Bitcoin Core's `AllocateFileRange`.
    fn preallocate(&self, file: &File) -> Result<(), StoreError> {
        let current = file.metadata().map_err(StoreError::Io)?.len();
        let boundary = ((current / self.chunk_size) + 1) * self.chunk_size;
        if current < boundary {
            let mut f = file.try_clone().map_err(StoreError::Io)?;
            f.seek(SeekFrom::Start(boundary - 1))
                .map_err(StoreError::Io)?;
            f.write_all(&[0u8]).map_err(StoreError::Io)?;
        }
        Ok(())
    }
}

// ── BlockFileManager ──────────────────────────────────────────────────────────

/// Entry point for all flat-file block and undo I/O.
///
/// Tracks the active file, writes records with the magic+size header,
/// returns `FlatFilePos` values for storage in the block index, and
/// rotates to a new file when the current one is full.
///
/// Equivalent to the flat-file portion of Bitcoin Core's `BlockManager`.
pub struct BlockFileManager {
    blocks: FlatFileSeq,
    undo: FlatFileSeq,
    magic: Magic,
    current_file: u32,
    /// Bytes written into the current block file, including headers.
    pub current_size: u64,
}

/// A thread-safe, cloneable handle for reading raw block/undo records.
#[derive(Debug, Clone)]
pub struct BlockFileReader {
    blocks: FlatFileSeq,
    undo: FlatFileSeq,
    magic: Magic,
}

impl BlockFileReader {
    pub fn read_block(&self, pos: FlatFilePos) -> Result<Vec<u8>, StoreError> {
        read_record(&self.blocks, pos, self.magic)
    }

    pub fn read_undo(&self, pos: FlatFilePos) -> Result<Vec<u8>, StoreError> {
        read_record(&self.undo, pos, self.magic)
    }
}

impl BlockFileManager {
    /// Open (or resume) the flat-file sequence.
    ///
    /// `last_file` is the file number read from `CHAIN_META` on startup.
    /// Pass `0` for a fresh database.
    pub fn new(dir: impl Into<PathBuf>, magic: Magic, last_file: u32) -> Result<Self, StoreError> {
        let dir = dir.into();
        let blocks = FlatFileSeq::new(dir.join("blocks"), "blk", BLOCK_FILE_CHUNK);
        let undo = FlatFileSeq::new(dir.join("blocks"), "rev", UNDO_FILE_CHUNK);

        let current_size = {
            let path = blocks.path(last_file);
            if path.exists() {
                fs::metadata(&path).map_err(StoreError::Io)?.len()
            } else {
                0
            }
        };

        Ok(Self {
            blocks,
            undo,
            magic,
            current_file: last_file,
            current_size,
        })
    }

    /// Obtain a thread-safe reader handle.
    pub fn reader(&self) -> BlockFileReader {
        BlockFileReader {
            blocks: self.blocks.clone(),
            undo: self.undo.clone(),
            magic: self.magic,
        }
    }

    // ── Write ─────────────────────────────────────────────────────────────────

    /// Append a raw block to the current `blk*.dat` file.
    ///
    /// Rotates to a new file if the current one would exceed
    /// `MAX_BLOCK_FILE_SIZE`. Returns the `FlatFilePos` of the data
    /// payload (offset is past the 8-byte header).
    pub fn write_block(&mut self, raw_block: &[u8]) -> Result<FlatFilePos, StoreError> {
        let record_len = 8 + raw_block.len() as u64;

        if self.current_size + record_len > MAX_BLOCK_FILE_SIZE && self.current_size > 0 {
            self.blocks.finalize(self.current_file, self.current_size)?;
            self.current_file += 1;
            self.current_size = 0;
        }

        let write_at = self.current_size;
        let mut file = self.blocks.open_for_write(self.current_file)?;
        file.seek(SeekFrom::Start(write_at))
            .map_err(StoreError::Io)?;

        self.write_record(&mut file, raw_block)?;
        file.sync_all().map_err(StoreError::Io)?;
        drop(file); // Explicitly close on Windows before any read attempts

        let data_offset = write_at + 8;
        self.current_size += record_len;

        Ok(FlatFilePos::new(self.current_file, data_offset as u32))
    }

    /// Append undo data to the `rev*.dat` file paired with `blk_file`.
    ///
    /// Undo data always goes to the `rev` file with the same number as the
    /// `blk` file that holds the block. Returns the `FlatFilePos` and the
    /// updated undo file size (caller persists this in `BlockFileInfo`).
    pub fn write_undo(
        &self,
        blk_file: u32,
        undo_data: &[u8],
        current_undo_size: u64,
    ) -> Result<(FlatFilePos, u64), StoreError> {
        let write_at = current_undo_size;
        let mut file = self.undo.open_for_write(blk_file)?;
        file.seek(SeekFrom::Start(write_at))
            .map_err(StoreError::Io)?;

        self.write_record(&mut file, undo_data)?;
        file.sync_all().map_err(StoreError::Io)?;
        drop(file); // Explicitly close on Windows before any read attempts

        let data_offset = write_at + 8;
        let new_undo_size = current_undo_size + 8 + undo_data.len() as u64;

        Ok((
            FlatFilePos::new(blk_file, data_offset as u32),
            new_undo_size,
        ))
    }

    // ── Read ──────────────────────────────────────────────────────────────────

    /// Read a block from its `FlatFilePos`.
    pub fn read_block(&self, pos: FlatFilePos) -> Result<Vec<u8>, StoreError> {
        read_record(&self.blocks, pos, self.magic)
    }

    /// Read undo data from its `FlatFilePos`.
    pub fn read_undo(&self, pos: FlatFilePos) -> Result<Vec<u8>, StoreError> {
        read_record(&self.undo, pos, self.magic)
    }

    // ── State ─────────────────────────────────────────────────────────────────

    /// The currently active block file number.
    ///
    /// Must be persisted to `CHAIN_META` under `KEY_LAST_FILE` on every
    /// file rotation so the manager can resume after restart.
    pub fn current_file(&self) -> u32 {
        self.current_file
    }

    /// Flush the current block file to the OS buffer.
    pub fn flush(&self) -> Result<(), StoreError> {
        if self.current_size == 0 {
            return Ok(());
        }
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(self.blocks.path(self.current_file))
            .map_err(StoreError::Io)?;
        file.sync_data().map_err(StoreError::Io)
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    /// Write `magic (4) + size (4 LE) + data` to `file`.
    fn write_record(&self, file: &mut File, data: &[u8]) -> Result<(), StoreError> {
        let header = Encoder::new()
            .encode_field(&self.magic)
            .encode_field(&(data.len() as u32))
            .finish();

        file.write_all(&header).map_err(StoreError::Io)?;
        file.write_all(data).map_err(StoreError::Io)?;
        Ok(())
    }
}

// ── Read helper ───────────────────────────────────────────────────────────────

/// Read the data payload of a record given its `FlatFilePos`.
///
/// `pos.offset` points to the data start. We seek back 4 bytes to read
/// the size field, then forward to read that many bytes of data.
fn read_record(seq: &FlatFileSeq, pos: FlatFilePos, _magic: Magic) -> Result<Vec<u8>, StoreError> {
    let mut file = seq.open_for_read(pos.file)?;

    let size_at = (pos.offset as u64).checked_sub(4).ok_or_else(|| {
        StoreError::Decode(format!(
            "FlatFilePos offset {} is too small to hold a size header",
            pos.offset
        ))
    })?;

    file.seek(SeekFrom::Start(size_at))
        .map_err(StoreError::Io)?;

    let mut size_buf = [0u8; 4];
    file.read_exact(&mut size_buf)
        .map_err(|_| StoreError::BlockFileUnavailable {
            file: pos.file,
            offset: pos.offset,
        })?;

    let (size, dec) = Decoder::new(&size_buf)
        .decode_field::<u32>("record::size")
        .map_err(StoreError::WireDecode)?;
    dec.finish("record::size").map_err(StoreError::WireDecode)?;

    let mut data = vec![0u8; size as usize];
    file.read_exact(&mut data)
        .map_err(|_| StoreError::BlockFileUnavailable {
            file: pos.file,
            offset: pos.offset,
        })?;

    Ok(data)
}
