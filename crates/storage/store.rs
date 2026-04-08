use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

use bitcrab_common::types::block::{BlockHeader, BlockHeight, BlockIndex};
use bitcrab_common::types::hash::BlockHash;
use bitcrab_common::wire::decode::{BitcoinDecode, Decoder};
use bitcrab_common::FlatFilePos;

use crate::api::{tables, StorageBackend};
use crate::backend::in_memory::InMemoryBackend;
#[cfg(feature = "rocksdb")]
use crate::backend::rocksdb::RocksDBBackend;
use crate::block_file::{BlockFileManager, BlockFileReader, Magic};
use crate::error::StoreError;
use crate::worker::{StorageWorker, WriteMessage};

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
/// - Reads: Direct and concurrent via Arc<dyn StorageBackend>.
/// - Writes: Sequential and asynchronous via StorageWorker actor.
#[derive(Clone)]
pub struct Store {
    backend: Arc<dyn StorageBackend>,
    block_reader: BlockFileReader,
    worker_tx: mpsc::Sender<WriteMessage>,
}

impl Store {
    /// Open or create a new store at the given path.
    pub fn new(
        path: impl Into<PathBuf>,
        engine: EngineType,
        magic: Magic,
    ) -> Result<Self, StoreError> {
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

        let block_file_manager = BlockFileManager::new(path, magic, last_file)?;
        let block_reader = block_file_manager.reader();

        // Start the sequential write worker
        let (tx, rx) = mpsc::channel(1024);
        let worker = StorageWorker::new(Arc::clone(&backend), block_file_manager, rx);

        tokio::spawn(async move {
            worker.run().await;
        });

        Ok(Self {
            backend,
            block_reader,
            worker_tx: tx,
        })
    }

    /// Convenience for creating a fresh in-memory store for tests.
    pub fn in_memory(magic: Magic) -> Result<Self, StoreError> {
        Self::new("", EngineType::InMemory, magic)
    }

    // ── Headers ───────────────────────────────────────────────────────────────

    /// Store a block header and update the chain tip if `is_best` is true.
    pub async fn store_header(
        &self,
        header: BlockHeader, // Move header in
        height: BlockHeight,
        is_best: bool,
    ) -> Result<(), StoreError> {
        let (tx, rx) = oneshot::channel();
        self.worker_tx
            .send(WriteMessage::StoreHeader {
                header,
                height,
                is_best,
                reply_to: tx,
            })
            .await
            .map_err(|_| StoreError::Custom("storage worker dead".into()))?;

        rx.await
            .map_err(|_| StoreError::Custom("storage worker dropped response".into()))?
    }

    /// Retrieve a block index (header + metadata) by hash.
    /// Performs a direct thread-safe read from the backend.
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
        dec.finish("BlockIndex")
            .map_err(|e| StoreError::Decode(e.to_string()))?;

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

    /// Fetch a coin from the UTXO set by its outpoint.
    pub fn get_coin(&self, outpoint: &bitcrab_common::types::transaction::OutPoint) -> Result<Option<bitcrab_common::types::coin::Coin>, StoreError> {
        let read = self.backend.begin_read()?;
        
        // Key: PREFIX_COIN (C) + txid + vout
        let mut key = Vec::with_capacity(37);
        key.push(tables::PREFIX_COIN);
        key.extend_from_slice(outpoint.txid.as_bytes());
        key.extend_from_slice(&outpoint.vout.to_le_bytes());

        let Some(bytes) = read.get(tables::UTXOS, &key)? else {
            return Ok(None);
        };

        let (coin, dec) = bitcrab_common::types::coin::Coin::decode(bitcrab_common::wire::decode::Decoder::new(&bytes))
            .map_err(|e| StoreError::Decode(format!("failed to decode Coin: {}", e)))?;
        dec.finish("Coin")
            .map_err(|e| StoreError::Decode(e.to_string()))?;

        Ok(Some(coin))
    }

    /// Atomically update the UTXO set and current tip.
    pub async fn update_utxos(
        &self,
        coins: std::collections::HashMap<bitcrab_common::types::transaction::OutPoint, crate::worker::CoinUpdate>,
        best_block_hash: Option<bitcrab_common::types::hash::BlockHash>,
    ) -> Result<(), StoreError> {
        let (tx, rx) = oneshot::channel();
        self.worker_tx
            .send(WriteMessage::UpdateUtxoSet {
                coins,
                best_block: best_block_hash,
                reply_to: tx,
            })
            .await
            .map_err(|_| StoreError::Custom("storage worker dead".into()))?;

        rx.await
            .map_err(|_| StoreError::Custom("storage worker dropped response".into()))?
    }

    // ── Blocks ────────────────────────────────────────────────────────────────

    /// Append a full block to disk and update its index record with the file pointer.
    pub async fn store_block(
        &self,
        header: BlockHeader,
        height: BlockHeight,
        raw_block: Vec<u8>,
    ) -> Result<FlatFilePos, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.worker_tx
            .send(WriteMessage::StoreBlock {
                header,
                height,
                raw_block,
                reply_to: tx,
            })
            .await
            .map_err(|_| StoreError::Custom("storage worker dead".into()))?;

        rx.await
            .map_err(|_| StoreError::Custom("storage worker dropped response".into()))?
    }

    /// Store the reversal state (undo data) for a specific block.
    pub async fn store_undo(
        &self,
        block_hash: bitcrab_common::types::hash::BlockHash,
        undo_data: bitcrab_common::types::undo::BlockUndo,
    ) -> Result<(), StoreError> {
        let (tx, rx) = oneshot::channel();
        self.worker_tx
            .send(WriteMessage::StoreUndo {
                block_hash,
                undo_data,
                reply_to: tx,
            })
            .await
            .map_err(|_| StoreError::Custom("storage worker dead".into()))?;

        rx.await
            .map_err(|_| StoreError::Custom("storage worker dropped response".into()))?
    }

    /// Retrieve raw block bytes from disk by hash.
    /// Performs direct concurrent disk read without worker mediation.
    pub fn get_block(&self, hash: &BlockHash) -> Result<Option<Vec<u8>>, StoreError> {
        let Some(index) = self.get_block_index(hash)? else {
            return Ok(None);
        };

        let Some(pos) = index.file_pos else {
            return Ok(None);
        };

        let data = self.block_reader.read_block(pos)?;
        Ok(Some(data))
    }

    /// Flush buffers to disk.
    pub async fn flush(&self) -> Result<(), StoreError> {
        let (tx, rx) = oneshot::channel();
        self.worker_tx
            .send(WriteMessage::Flush { reply_to: tx })
            .await
            .map_err(|_| StoreError::Custom("storage worker dead".into()))?;

        rx.await
            .map_err(|_| StoreError::Custom("storage worker dropped response".into()))?
    }
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").finish_non_exhaustive()
    }
}
