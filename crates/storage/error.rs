use thiserror::Error;

/// Storage layer errors for the bitcrab Bitcoin node.
///
/// Covers only backend I/O and data integrity concerns.
/// Consensus and validation errors belong in `bitcrab-node`.
#[derive(Debug, Error)]
pub enum StoreError {
    // ── Backend ───────────────────────────────────────────────────────────────
    #[error("wire decode error: {0}")]
    WireDecode(#[from] bitcrab_common::wire::DecodeError),

    /// A RocksDB operation failed.
    #[cfg(feature = "rocksdb")]
    #[error("rocksdb error: {0}")]
    RocksDB(#[from] rocksdb::Error),

    /// An OS-level I/O error occurred while reading from or writing to disk.
    ///
    /// Covers both RocksDB file I/O and flat block file (`blk*.dat`) operations.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A shared-state lock was poisoned by a panicking thread.
    #[error("lock poisoned")]
    LockPoisoned,

    // ── Serialization ─────────────────────────────────────────────────────────
    /// Failed to decode a value retrieved from the database or a block file.
    ///
    /// Indicates corrupt data or a schema mismatch between writer and reader.
    #[error("decode error: {0}")]
    Decode(String),

    /// Failed to encode a value before writing it to the database or a block file.
    #[error("encode error: {0}")]
    Encode(String),

    // ── Chain state ───────────────────────────────────────────────────────────
    /// The best-block pointer has not been written to the UTXO table yet.
    ///
    /// Returned on first startup before genesis is stored.
    #[error("best block not found")]
    MissingBestBlock,

    /// A block was requested by hash but is not in the block index.
    ///
    /// The block index (`BLOCK_INDEX` table) holds metadata for all known
    /// blocks. This error means the hash is entirely unknown to this node.
    #[error("block not found in index")]
    MissingBlockIndex,

    /// A block file position is known but the flat file could not be read.
    ///
    /// The block index entry exists (`BLOCK_INDEX`) but the corresponding
    /// `blk*.dat` file is missing, truncated, or corrupt.
    #[error("block data unavailable at {file}:{offset}")]
    BlockFileUnavailable { file: u32, offset: u32 },

    // ── Schema versioning ─────────────────────────────────────────────────────
    /// The on-disk schema version does not match the compiled-in version.
    ///
    /// A re-index is required after upgrading the node binary.
    #[error("incompatible DB version: found v{found}, expected v{expected}")]
    IncompatibleDbVersion { found: u64, expected: u64 },

    /// No schema version file was found in the data directory.
    #[error("DB version file not found, expected v{expected}")]
    MissingDbVersion { expected: u64 },

    /// Catch-all for errors that have not yet been given a dedicated variant.
    ///
    /// Prefer adding a specific variant over reaching for this.
    #[error("{0}")]
    Custom(String),
}
