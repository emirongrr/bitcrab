use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use bitcrab_common::types::block::{BlockHeader, BlockHeight, BlockIndex};
use bitcrab_common::FlatFilePos;
use bitcrab_common::types::hash::BlockHash;
use bitcrab_common::wire::encode::Encoder;
use bitcrab_common::wire::decode::{BitcoinDecode, Decoder};

use crate::api::{StorageBackend, tables};
use crate::backend::in_memory::InMemoryBackend;
#[cfg(feature = "rocksdb")]
use crate::backend::rocksdb::RocksDBBackend;
use crate::block_file::{BlockFileManager, Magic};
use crate::error::StoreError;

/// Storage engine selection.
pub enum EngineType {
    /// Non-persistent in-memory storage for testing.
    InMemory,
    /// Persistent RocksDB storage.
    #[cfg(feature = "rocksdb")]
    RocksDB,
}

/// The high-level storage orchestrator for the bitcrab node.
///
/// Mirrors Bitcoin Core's architecture:
/// - Raw blocks are stored in append-only `blk*.dat` files.
/// - Metadata (block index, UTXO set) is stored in a key-value backend (RocksDB).
///
#[derive(Clone)]
pub struct Store {
    backend: Arc<dyn StorageBackend>,
    block_file_manager: Arc<RwLock<BlockFileManager>>,
}

impl Store {
    /// Open or create a new store at the given path.
    pub fn new(path: impl Into<PathBuf>, engine: EngineType, magic: Magic) -> Result<Self, StoreError> {
        let path = path.into();
        let backend: Arc<dyn StorageBackend> = match engine {
            EngineType::InMemory => Arc::new(InMemoryBackend::open()?),
            #[cfg(feature = "rocksdb")]
            EngineType::RocksDB => Arc::new(RocksDBBackend::open(&path)?),
        };

        // Recover last file number from metadata
        let last_file = {
            let read = backend.begin_read()?;
            read.get(tables::CHAIN_META, &[tables::KEY_LAST_FILE])?
                .map(|b| {
                    let mut arr = [0u8; 4];
                    arr.copy_from_slice(&b[..4]);
                    u32::from_le_bytes(arr)
                })
                .unwrap_or(0)
        };

        let block_file_manager = Arc::new(RwLock::new(BlockFileManager::new(path, magic, last_file)?));

        Ok(Self { backend, block_file_manager })
    }

    /// Convenience for creating a fresh in-memory store for tests.
    pub fn in_memory(magic: Magic) -> Result<Self, StoreError> {
        Self::new("", EngineType::InMemory, magic)
    }

    // ── Headers ───────────────────────────────────────────────────────────────

    /// Store a block header and update the chain tip if `is_best` is true.
    pub fn store_header(
        &self,
        header: &BlockHeader,
        height: BlockHeight,
        is_best: bool,
    ) -> Result<(), StoreError> {
        let hash = header.block_hash();
        let index = BlockIndex {
            header:   header.clone(),
            height,
            file_pos: None,
            undo_pos: None,
        };

        let mut write = self.backend.begin_write()?;
        
        // 1. Store index record: 'b' + hash -> BlockIndex
        let mut key = Vec::with_capacity(33);
        key.push(tables::PREFIX_BLOCK);
        key.extend_from_slice(hash.as_bytes());
        
        let value = Encoder::new().encode_field(&index).finish();
        write.put(tables::BLOCK_INDEX, &key, &value)?;

        // 2. Update best block if needed: 'B' -> hash
        if is_best {
            write.put(tables::UTXOS, &[tables::KEY_BEST_BLOCK], hash.as_bytes())?;
        }

        write.commit()
    }

    /// Retrieve a block index (header + metadata) by hash.
    pub fn get_block_index(&self, hash: &BlockHash) -> Result<Option<BlockIndex>, StoreError> {
        let read = self.backend.begin_read()?;
        
        let mut key = Vec::with_capacity(33);
        key.push(tables::PREFIX_BLOCK);
        key.extend_from_slice(hash.as_bytes());

        let Some(bytes) = read.get(tables::BLOCK_INDEX, &key)? else {
            return Ok(None);
        };

        let (index, dec) = BlockIndex::decode(Decoder::new(&bytes))
            .map_err(|e| StoreError::Decode(format!("failed to decode BlockIndex: {}", e)))?;
        dec.finish("BlockIndex").map_err(|e| StoreError::Decode(e.to_string()))?;
        
        Ok(Some(index))
    }

    /// Retrieve the hash of the current best block (tip).
    pub fn get_best_block(&self) -> Result<Option<BlockHash>, StoreError> {
        let read = self.backend.begin_read()?;
        let Some(bytes) = read.get(tables::UTXOS, &[tables::KEY_BEST_BLOCK])? else {
            return Ok(None);
        };

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32]);
        Ok(Some(BlockHash::from_bytes(arr)))
    }

    // ── Blocks ────────────────────────────────────────────────────────────────

    /// Append a full block to disk and update its index record with the file pointer.
    pub async fn store_block(&self, header: &BlockHeader, height: BlockHeight, raw_block: &[u8]) -> Result<FlatFilePos, StoreError> {
        let hash = header.block_hash();
        
        // 1. Write to blk*.dat
        let mut mgr = self.block_file_manager.write().await;
        let pos = mgr.write_block(raw_block)?;
        let last_file = mgr.current_file();
        drop(mgr);

        // 2. Update index with position
        let index = BlockIndex {
            header:   header.clone(),
            height,
            file_pos: Some(pos),
            undo_pos: None,
        };

        let mut write = self.backend.begin_write()?;
        
        let mut key = Vec::with_capacity(33);
        key.push(tables::PREFIX_BLOCK);
        key.extend_from_slice(hash.as_bytes());
        
        let value = Encoder::new().encode_field(&index).finish();
        write.put(tables::BLOCK_INDEX, &key, &value)?;

        // 3. Update last file in metadata
        write.put(tables::CHAIN_META, &[tables::KEY_LAST_FILE], &last_file.to_le_bytes())?;

        write.commit()?;
        
        Ok(pos)
    }

    /// Retrieve raw block bytes from disk by hash.
    pub async fn get_block(&self, hash: &BlockHash) -> Result<Option<Vec<u8>>, StoreError> {
        let Some(index) = self.get_block_index(hash)? else {
            return Ok(None);
        };

        let Some(pos) = index.file_pos else {
            return Ok(None);
        };

        let mgr = self.block_file_manager.read().await;
        let data = mgr.read_block(pos)?;
        
        Ok(Some(data))
    }
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").finish_non_exhaustive()
    }
}
