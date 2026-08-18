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
use crate::block_file::{BlockFileManager, Magic};
use crate::block_manager::WriteMessage;
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
/// - Reads: Direct and concurrent via Arc<dyn StorageBackend>.
/// - Writes: Sequential and asynchronous via BlockManager actor.
#[derive(Clone)]
pub struct Store {
    backend: Arc<dyn StorageBackend>,
    block_file_manager: BlockFileManager,
    write_tx: mpsc::Sender<WriteMessage>,
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

        // Start the sequential write worker
        let (tx, rx) = mpsc::channel(100);
        let worker = crate::block_manager::BlockManager::new(
            backend.clone(),
            block_file_manager.clone(),
            rx,
        );

        tokio::spawn(worker.run());

        Ok(Self {
            backend,
            block_file_manager,
            write_tx: tx,
        })
    }

    /// Convenience for creating a fresh in-memory store for tests.
    pub fn in_memory(magic: Magic) -> Result<Self, StoreError> {
        Self::new("", EngineType::InMemory, magic)
    }

    // â”€â”€ Headers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Store a block header and update the chain tip if `is_best` is true.
    pub async fn store_header(
        &self,
        header: BlockHeader, // Move header in
        height: BlockHeight,
        chain_work: bitcrab_common::types::hash::Hash256,
        is_best: bool,
    ) -> Result<(), StoreError> {
        let (tx, rx) = oneshot::channel();
        match self
            .write_tx
            .send(WriteMessage::StoreHeader {
                header,
                height,
                chain_work,
                is_best,
                reply_to: tx,
            })
            .await
        {
            Ok(_) => rx.await.map_err(|e| StoreError::Custom(e.to_string()))?,
            Err(e) => Err(StoreError::Custom(e.to_string())),
        }
    }

    /// Directly store/update a block index.
    pub async fn store_block_index(
        &self,
        hash: &BlockHash,
        index: BlockIndex,
    ) -> Result<(), StoreError> {
        let (tx, rx) = oneshot::channel();
        match self
            .write_tx
            .send(WriteMessage::StoreBlockIndex {
                hash: *hash,
                index,
                reply_to: tx,
            })
            .await
        {
            Ok(_) => rx.await.map_err(|e| StoreError::Custom(e.to_string()))?,
            Err(e) => Err(StoreError::Custom(e.to_string())),
        }
    }

    /// Atomically persist a validated header batch and optional best-header tip.
    pub async fn store_block_indexes(
        &self,
        indexes: Vec<(BlockHash, BlockIndex)>,
        best_tip: Option<BlockHash>,
    ) -> Result<(), StoreError> {
        let (tx, rx) = oneshot::channel();
        self.write_tx
            .send(WriteMessage::StoreBlockIndexes {
                indexes,
                best_tip,
                reply_to: tx,
            })
            .await
            .map_err(|_| StoreError::Custom("storage worker dead".into()))?;

        rx.await
            .map_err(|_| StoreError::Custom("storage worker dropped response".into()))?
    }
    /// Update the headers tip hash.
    pub async fn update_headers_tip(&self, hash: BlockHash) -> Result<(), StoreError> {
        let (tx, rx) = oneshot::channel();
        match self
            .write_tx
            .send(WriteMessage::UpdateHeadersTip { hash, reply_to: tx })
            .await
        {
            Ok(_) => rx.await.map_err(|e| StoreError::Custom(e.to_string()))?,
            Err(e) => Err(StoreError::Custom(e.to_string())),
        }
    }

    /// Directly update the header-height-to-hash index for self-healing.
    pub async fn store_header_index_only(
        &self,
        hash: BlockHash,
        height: u32,
    ) -> Result<(), StoreError> {
        let (tx, rx) = oneshot::channel();
        self.write_tx
            .send(WriteMessage::UpdateHeaderIndex {
                hash,
                height,
                reply_to: tx,
            })
            .await
            .map_err(|_| StoreError::Custom("storage worker dead".into()))?;

        rx.await
            .map_err(|_| StoreError::Custom("storage worker dropped response".into()))?
    }

    /// Update the current active tip hash.
    pub async fn update_active_tip(&self, hash: BlockHash) -> Result<(), StoreError> {
        let (tx, rx) = oneshot::channel();
        self.write_tx
            .send(WriteMessage::UpdateActiveTip { hash, reply_to: tx })
            .await
            .map_err(|_| StoreError::Custom("storage worker dead".into()))?;

        rx.await
            .map_err(|_| StoreError::Custom("storage worker dropped response".into()))?
    }

    /// Mark a block as having its data missing (delete datadir data but keep index).
    pub async fn delete_block(&self, hash: &BlockHash) -> Result<(), StoreError> {
        let (tx, rx) = oneshot::channel();
        self.write_tx
            .send(WriteMessage::DeleteBlock {
                hash: *hash,
                reply_to: tx,
            })
            .await
            .map_err(|_| StoreError::Custom("storage worker dead".into()))?;

        rx.await
            .map_err(|_| StoreError::Custom("storage worker dropped response".into()))?
    }

    /// Delete a height-to-hash mapping from CHAIN_META.
    pub async fn delete_height_mapping(&self, height: u32) -> Result<(), StoreError> {
        let (tx, rx) = oneshot::channel();
        self.write_tx
            .send(WriteMessage::DeleteHeightMapping {
                height,
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

    /// Retrieve the hash of the current best header (tip of the header chain).
    pub fn get_headers_tip(&self) -> Result<Option<BlockHash>, StoreError> {
        let read = self.backend.begin_read()?;
        let Some(bytes) = read.get(tables::UTXOS, &[tables::KEY_HEADERS_TIP])? else {
            return Ok(None);
        };

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32]);
        Ok(Some(BlockHash::from_bytes(arr)))
    }

    /// Retrieve the hash of the current best validated block (tip).
    pub fn get_best_block(&self) -> Result<Option<BlockHash>, StoreError> {
        let read = self.backend.begin_read()?;
        let Some(bytes) = read.get(tables::UTXOS, &[tables::KEY_BEST_BLOCK])? else {
            return Ok(None);
        };

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32]);
        Ok(Some(BlockHash::from_bytes(arr)))
    }

    /// Retrieve a block hash by its height.
    pub fn get_block_hash(&self, height: u32) -> Result<Option<BlockHash>, StoreError> {
        let read = self.backend.begin_read()?;

        let mut key = Vec::with_capacity(5);
        key.push(tables::PREFIX_HEIGHT);
        key.extend_from_slice(&height.to_be_bytes());

        let Some(bytes) = read.get(tables::CHAIN_META, &key)? else {
            return Ok(None);
        };

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32]);
        Ok(Some(BlockHash::from_bytes(arr)))
    }

    /// Lookup block hash by its height in the header chain.
    /// Used for difficulty retargeting during sync.
    pub fn get_block_hash_by_header_height(
        &self,
        height: u32,
    ) -> Result<Option<BlockHash>, StoreError> {
        let read = self.backend.begin_read()?;

        let mut key = Vec::with_capacity(5);
        key.push(tables::PREFIX_HEADER_HEIGHT);
        key.extend_from_slice(&height.to_be_bytes());

        let Some(bytes) = read.get(tables::CHAIN_META, &key)? else {
            return Ok(None);
        };

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32]);
        Ok(Some(BlockHash::from_bytes(arr)))
    }

    /// Retrieve the hash of the current highest downloaded full block.
    pub fn get_block_tip(&self) -> Result<Option<BlockHash>, StoreError> {
        let read = self.backend.begin_read()?;
        let Some(bytes) = read.get(tables::UTXOS, &[tables::KEY_BLOCK_TIP])? else {
            return Ok(None);
        };

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32]);
        Ok(Some(BlockHash::from_bytes(arr)))
    }

    /// Fetch a coin from the UTXO set by its outpoint.
    pub fn get_coin(
        &self,
        outpoint: &bitcrab_common::types::transaction::OutPoint,
    ) -> Result<Option<bitcrab_common::types::coin::Coin>, StoreError> {
        let read = self.backend.begin_read()?;

        // Key: PREFIX_COIN (C) + txid + vout
        let mut key = Vec::with_capacity(37);
        key.push(tables::PREFIX_COIN);
        key.extend_from_slice(outpoint.txid.as_bytes());
        key.extend_from_slice(&outpoint.vout.to_le_bytes());

        let Some(bytes) = read.get(tables::UTXOS, &key)? else {
            return Ok(None);
        };

        let (coin, dec) = bitcrab_common::types::coin::Coin::decode(
            bitcrab_common::wire::decode::Decoder::new(&bytes),
        )
        .map_err(|e| StoreError::Decode(format!("failed to decode Coin: {}", e)))?;
        dec.finish("Coin")
            .map_err(|e| StoreError::Decode(e.to_string()))?;

        Ok(Some(coin))
    }

    /// Atomically update the UTXO set, height index, and current tip.
    pub async fn update_utxos(
        &self,
        coins: std::collections::HashMap<
            bitcrab_common::types::transaction::OutPoint,
            crate::block_manager::CoinUpdate,
        >,
        best_block_hash: Option<bitcrab_common::types::hash::BlockHash>,
        connected_blocks: Vec<(u32, bitcrab_common::types::hash::BlockHash)>,
    ) -> Result<(), StoreError> {
        let (tx, rx) = oneshot::channel();
        self.write_tx
            .send(WriteMessage::UpdateUtxoSet {
                coins,
                best_block: best_block_hash,
                connected_blocks,
                reply_to: tx,
            })
            .await
            .map_err(|_| StoreError::Custom("storage worker dead".into()))?;

        rx.await
            .map_err(|_| StoreError::Custom("storage worker dropped response".into()))?
    }

    // â”€â”€ Blocks â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Append a full block to disk and update its index record with the file pointer.
    pub async fn store_block(
        &self,
        header: BlockHeader,
        height: BlockHeight,
        chain_work: bitcrab_common::types::hash::Hash256,
        raw_block: Vec<u8>,
    ) -> Result<FlatFilePos, StoreError> {
        let (tx, rx) = oneshot::channel();
        self.write_tx
            .send(WriteMessage::StoreBlock {
                header,
                height,
                chain_work,
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
        self.write_tx
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

        let data = self.block_file_manager.read_block(pos)?;
        Ok(Some(data))
    }

    /// Retrieve a block's undo data — the coins it spent — from disk.
    ///
    /// Mirrors `get_block`: the undo record lives in the same numbered file as
    /// the block, at the position recorded in the block index.
    ///
    /// `Ok(None)` means we have no undo data for this block, which is normal
    /// for a block that was never connected, and for the genesis block. It is
    /// the caller's job to treat that as "cannot disconnect" rather than as
    /// "nothing to restore" — those are very different things for the UTXO set.
    pub fn get_undo(
        &self,
        hash: &BlockHash,
    ) -> Result<Option<bitcrab_common::types::undo::BlockUndo>, StoreError> {
        use bitcrab_common::types::undo::BlockUndo;
        use bitcrab_common::wire::decode::{BitcoinDecode, Decoder};

        let Some(index) = self.get_block_index(hash)? else {
            return Ok(None);
        };
        let Some(pos) = index.undo_pos else {
            return Ok(None);
        };

        let bytes = self.block_file_manager.read_undo(pos)?;
        let (undo, dec) =
            BlockUndo::decode(Decoder::new(&bytes)).map_err(StoreError::WireDecode)?;
        dec.finish("BlockUndo").map_err(StoreError::WireDecode)?;
        Ok(Some(undo))
    }

    /// Flush buffers to disk.
    pub async fn flush(&self) -> Result<(), StoreError> {
        let (tx, rx) = oneshot::channel();
        self.write_tx
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
