//! Sequential write worker for the storage engine.
//!
//! Handles all mutations to the block files and index to ensure
//! strict Bitcoin-compatible ordering and file integrity.

use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info};

use bitcrab_common::types::block::{BlockHeader, BlockHeight, BlockIndex};
use bitcrab_common::wire::encode::Encoder;
use bitcrab_common::FlatFilePos;

use crate::api::{tables, StorageBackend};
use crate::block_file::BlockFileManager;
use crate::error::StoreError;

/// Messages sent to the StorageWorker.
pub enum WriteMessage {
    /// Store a block header and update index.
    StoreHeader {
        header: BlockHeader,
        height: BlockHeight,
        is_best: bool,
        reply_to: oneshot::Sender<Result<(), StoreError>>,
    },
    /// Store a full block, append to blk*.dat, and update index.
    StoreBlock {
        header: BlockHeader,
        height: BlockHeight,
        raw_block: Vec<u8>,
        reply_to: oneshot::Sender<Result<FlatFilePos, StoreError>>,
    },
    /// Store reversal state for reorg support.
    StoreUndo {
        block_hash: bitcrab_common::types::hash::BlockHash,
        undo_data: bitcrab_common::types::undo::BlockUndo,
        reply_to: oneshot::Sender<Result<(), StoreError>>,
    },
    /// Batch update the UTXO set.
    UpdateUtxoSet {
        coins: std::collections::HashMap<bitcrab_common::types::transaction::OutPoint, crate::worker::CoinUpdate>,
        best_block: Option<bitcrab_common::types::hash::BlockHash>,
        reply_to: oneshot::Sender<Result<(), StoreError>>,
    },
    /// Flush all pending writes to disk.
    Flush {
        reply_to: oneshot::Sender<Result<(), StoreError>>,
    },
}

/// The internal worker that performs sequential writes.
pub struct StorageWorker {
    backend: Arc<dyn StorageBackend>,
    block_file_manager: BlockFileManager, // Now owned exclusively by the worker
    receiver: mpsc::Receiver<WriteMessage>,
}

impl StorageWorker {
    pub fn new(
        backend: Arc<dyn StorageBackend>,
        block_file_manager: BlockFileManager,
        receiver: mpsc::Receiver<WriteMessage>,
    ) -> Self {
        Self {
            backend,
            block_file_manager,
            receiver,
        }
    }

    /// Run the worker event loop.
    pub async fn run(mut self) {
        debug!("[storage-worker] started");

        while let Some(msg) = self.receiver.recv().await {
            match msg {
                WriteMessage::StoreHeader {
                    header,
                    height,
                    is_best,
                    reply_to,
                } => {
                    let res = self.handle_store_header(header, height, is_best);
                    let _ = reply_to.send(res);
                }
                WriteMessage::StoreBlock {
                    header,
                    height,
                    raw_block,
                    reply_to,
                } => {
                    let res = self.handle_store_block(header, height, &raw_block).await;
                    let _ = reply_to.send(res);
                }
                WriteMessage::UpdateUtxoSet {
                    coins,
                    best_block,
                    reply_to,
                } => {
                    let res = self.handle_update_utxo_set(coins, best_block);
                    let _ = reply_to.send(res);
                }
                WriteMessage::StoreUndo {
                    block_hash,
                    undo_data,
                    reply_to,
                } => {
                    let res = self.handle_store_undo(block_hash, undo_data);
                    let _ = reply_to.send(res);
                }
                WriteMessage::Flush { reply_to } => {
                    let res = self.block_file_manager.flush();
                    let _ = reply_to.send(res);
                }
            }
        }

        info!("[storage-worker] terminated");
    }

    fn handle_store_header(
        &self,
        header: BlockHeader,
        height: BlockHeight,
        is_best: bool,
    ) -> Result<(), StoreError> {
        let hash = header.block_hash();
        let index = BlockIndex {
            header: header.clone(),
            height,
            file_pos: None,
            undo_pos: None,
        };

        let mut write = self.backend.begin_write()?;

        let mut key = Vec::with_capacity(33);
        key.push(tables::PREFIX_BLOCK);
        key.extend_from_slice(hash.as_bytes());

        let value = Encoder::new().encode_field(&index).finish();
        write.put(tables::BLOCK_INDEX, &key, &value)?;

        if is_best {
            write.put(tables::UTXOS, &[tables::KEY_BEST_BLOCK], hash.as_bytes())?;
        }

        write.commit()
    }

    async fn handle_store_block(
        &mut self,
        header: BlockHeader,
        height: BlockHeight,
        raw_block: &[u8],
    ) -> Result<FlatFilePos, StoreError> {
        let hash = header.block_hash();

        // 1. Write to blk*.dat (Sequential access guaranteed here)
        let pos = self.block_file_manager.write_block(raw_block)?;
        let last_file = self.block_file_manager.current_file();

        // 2. Update index with position
        let index = BlockIndex {
            header: header.clone(),
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
        write.put(
            tables::CHAIN_META,
            &[tables::KEY_LAST_FILE],
            &last_file.to_le_bytes(),
        )?;

        write.commit()?;

        Ok(pos)
    }

    fn handle_update_utxo_set(
        &self,
        coins: std::collections::HashMap<bitcrab_common::types::transaction::OutPoint, CoinUpdate>,
        best_block: Option<bitcrab_common::types::hash::BlockHash>,
    ) -> Result<(), StoreError> {
        let mut write = self.backend.begin_write()?;

        for (outpoint, update) in coins {
            let mut key = Vec::with_capacity(37);
            key.push(tables::PREFIX_COIN);
            key.extend_from_slice(outpoint.txid.as_bytes());
            key.extend_from_slice(&outpoint.vout.to_le_bytes());

            match update {
                CoinUpdate::Add(coin) => {
                    let value = bitcrab_common::wire::encode::Encoder::new()
                        .encode_field(&coin)
                        .finish();
                    write.put(tables::UTXOS, &key, &value)?;
                }
                CoinUpdate::Remove => {
                    write.delete(tables::UTXOS, &key)?;
                }
            }
        }

        if let Some(hash) = best_block {
            write.put(tables::UTXOS, &[tables::KEY_BEST_BLOCK], hash.as_bytes())?;
        }

        write.commit()
    }

    fn handle_store_undo(
        &self,
        block_hash: bitcrab_common::types::hash::BlockHash,
        undo_data: bitcrab_common::types::undo::BlockUndo,
    ) -> Result<(), StoreError> {
        let mut write = self.backend.begin_write()?;
        let value = Encoder::new().encode_field(&undo_data).finish();
        
        write.put(tables::BLOCK_UNDO, block_hash.as_bytes(), &value)?;
        write.commit()
    }
}

pub enum CoinUpdate {
    /// Add or update a coin in the UTXO set.
    Add(bitcrab_common::types::coin::Coin),
    /// Remove a coin (spent).
    Remove,
}
