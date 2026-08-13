//! Sequential write worker for the storage engine.
//!
//! Handles all mutations to the block files and index to ensure
//! strict Bitcoin-compatible ordering and file integrity.

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};
use tokio::sync::{mpsc, oneshot};
use tracing::info;

use bitcrab_common::types::block::{BlockHeader, BlockHeight, BlockIndex};
use bitcrab_common::types::hash::BlockHash;
use bitcrab_common::wire::decode::BitcoinDecode;
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
        chain_work: bitcrab_common::types::hash::Hash256,
        is_best: bool,
        reply_to: oneshot::Sender<Result<(), StoreError>>,
    },
    /// Store a full block, append to blk*.dat, and update index.
    StoreBlock {
        header: BlockHeader,
        height: BlockHeight,
        chain_work: bitcrab_common::types::hash::Hash256,
        raw_block: Vec<u8>,
        reply_to: oneshot::Sender<Result<FlatFilePos, StoreError>>,
    },
    /// Directly store/update a block index.
    StoreBlockIndex {
        hash: bitcrab_common::types::hash::BlockHash,
        index: BlockIndex,
        reply_to: oneshot::Sender<Result<(), StoreError>>,
    },
    /// Atomically store a validated header batch and its best tip.
    StoreBlockIndexes {
        indexes: Vec<(bitcrab_common::types::hash::BlockHash, BlockIndex)>,
        best_tip: Option<bitcrab_common::types::hash::BlockHash>,
        reply_to: oneshot::Sender<Result<(), StoreError>>,
    },
    /// Store reversal state for reorg support.
    StoreUndo {
        block_hash: bitcrab_common::types::hash::BlockHash,
        undo_data: bitcrab_common::types::undo::BlockUndo,
        reply_to: oneshot::Sender<Result<(), StoreError>>,
    },
    /// Batch update the UTXO set and atomic chain state.
    UpdateUtxoSet {
        coins: std::collections::HashMap<bitcrab_common::types::transaction::OutPoint, CoinUpdate>,
        best_block: Option<bitcrab_common::types::hash::BlockHash>,
        /// New height-to-hash mappings to be committed atomically.
        connected_blocks: Vec<(u32, bitcrab_common::types::hash::BlockHash)>,
        reply_to: oneshot::Sender<Result<(), StoreError>>,
    },
    /// Update the current active tip hash.
    UpdateActiveTip {
        hash: bitcrab_common::types::hash::BlockHash,
        reply_to: oneshot::Sender<Result<(), StoreError>>,
    },
    /// Update the headers tip hash.
    UpdateHeadersTip {
        hash: bitcrab_common::types::hash::BlockHash,
        reply_to: oneshot::Sender<Result<(), StoreError>>,
    },
    DeleteBlock {
        hash: bitcrab_common::types::hash::BlockHash,
        reply_to: oneshot::Sender<Result<(), StoreError>>,
    },
    /// Rollback: delete a height-to-hash mapping.
    DeleteHeightMapping {
        height: u32,
        reply_to: oneshot::Sender<Result<(), StoreError>>,
    },
    /// Directly update a header height index.
    UpdateHeaderIndex {
        hash: bitcrab_common::types::hash::BlockHash,
        height: u32,
        reply_to: oneshot::Sender<Result<(), StoreError>>,
    },
    /// Flush all pending writes to disk.
    Flush {
        reply_to: oneshot::Sender<Result<(), StoreError>>,
    },
}

/// Sequential write worker (BlockManager) for the storage engine.
/// Bitcoin Core Ref: validation.cpp / blockstorage.cpp
pub struct BlockManager {
    backend: Arc<dyn StorageBackend>,
    block_file_manager: BlockFileManager,
    rx: mpsc::Receiver<WriteMessage>,
    last_known_tip_height: u32,
    undo_sizes: HashMap<u32, u64>,
    pending_undo_indexes: HashMap<BlockHash, BlockIndex>,
}

impl BlockManager {
    pub fn new(
        backend: Arc<dyn StorageBackend>,
        block_file_manager: BlockFileManager,
        rx: mpsc::Receiver<WriteMessage>,
    ) -> Self {
        Self {
            backend,
            block_file_manager,
            rx,
            last_known_tip_height: 0,
            undo_sizes: HashMap::new(),
            pending_undo_indexes: HashMap::new(),
        }
    }

    pub async fn run(mut self) {
        info!("[block-manager] started");

        // Initialize tip height from DB on startup
        self.last_known_tip_height = match self.backend.begin_read() {
            Ok(read) => match read.get(tables::UTXOS, &[tables::KEY_BLOCK_TIP]) {
                Ok(Some(tip_hash_bytes)) => {
                    let tip_hash =
                        BlockHash::from_bytes(tip_hash_bytes.try_into().unwrap_or([0u8; 32]));
                    let mut tip_key = Vec::with_capacity(33);
                    tip_key.push(tables::PREFIX_BLOCK);
                    tip_key.extend_from_slice(tip_hash.as_bytes());

                    match read.get(tables::BLOCK_INDEX, &tip_key) {
                        Ok(Some(idx_bytes)) => BlockIndex::decode(
                            bitcrab_common::wire::decode::Decoder::new(&idx_bytes),
                        )
                        .map(|(idx, _)| idx.height.0)
                        .unwrap_or(0),
                        _ => 0,
                    }
                }
                _ => 0,
            },
            _ => 0,
        };

        info!(
            "[block-manager] initialized with disk tip height {}",
            self.last_known_tip_height
        );

        let mut backlog = VecDeque::new();
        loop {
            let msg = if let Some(msg) = backlog.pop_front() {
                msg
            } else {
                let Some(msg) = self.rx.recv().await else {
                    break;
                };
                msg
            };

            match msg {
                WriteMessage::StoreHeader {
                    header,
                    height,
                    chain_work,
                    is_best,
                    reply_to,
                } => {
                    let res = self.handle_store_header(header, height, chain_work, is_best);
                    let _ = reply_to.send(res);
                }
                WriteMessage::StoreBlock {
                    header,
                    height,
                    chain_work,
                    raw_block,
                    reply_to,
                } => {
                    let mut blocks = vec![(header, height, chain_work, raw_block)];
                    let mut replies = vec![reply_to];

                    while blocks.len() < 64 {
                        match self.rx.try_recv() {
                            Ok(WriteMessage::StoreBlock {
                                header,
                                height,
                                chain_work,
                                raw_block,
                                reply_to,
                            }) => {
                                blocks.push((header, height, chain_work, raw_block));
                                replies.push(reply_to);
                            }
                            Ok(other) => {
                                backlog.push_back(other);
                                break;
                            }
                            Err(_) => break,
                        }
                    }

                    match self.handle_store_blocks(blocks).await {
                        Ok(positions) => {
                            for (reply, pos) in replies.into_iter().zip(positions) {
                                let _ = reply.send(Ok(pos));
                            }
                        }
                        Err(error) => {
                            let message = error.to_string();
                            for reply in replies {
                                let _ = reply.send(Err(StoreError::Custom(message.clone())));
                            }
                        }
                    }
                }
                WriteMessage::StoreBlockIndex {
                    hash,
                    index,
                    reply_to,
                } => {
                    let res = self.handle_store_block_index(&hash, index);
                    let _ = reply_to.send(res);
                }
                WriteMessage::StoreBlockIndexes {
                    indexes,
                    best_tip,
                    reply_to,
                } => {
                    let res = self.handle_store_block_indexes(indexes, best_tip);
                    let _ = reply_to.send(res);
                }
                WriteMessage::UpdateUtxoSet {
                    coins,
                    best_block,
                    connected_blocks,
                    reply_to,
                } => {
                    let res = self.handle_update_utxo_set(coins, best_block, connected_blocks);
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
                WriteMessage::UpdateActiveTip { hash, reply_to } => {
                    let res = self.handle_update_active_tip(&hash);
                    let _ = reply_to.send(res);
                }
                WriteMessage::UpdateHeadersTip { hash, reply_to } => {
                    let res = self.handle_update_headers_tip(&hash);
                    let _ = reply_to.send(res);
                }
                WriteMessage::DeleteBlock { hash, reply_to } => {
                    let res = self.handle_delete_block(&hash);
                    let _ = reply_to.send(res);
                }
                WriteMessage::DeleteHeightMapping { height, reply_to } => {
                    let res = self.handle_delete_height_mapping(height);
                    let _ = reply_to.send(res);
                }
                WriteMessage::UpdateHeaderIndex {
                    hash,
                    height,
                    reply_to,
                } => {
                    let res = self.handle_update_header_index(&hash, height);
                    let _ = reply_to.send(res);
                }
                WriteMessage::Flush { reply_to } => {
                    let res = self.block_file_manager.flush();
                    let _ = reply_to.send(res);
                }
            }
        }

        info!("[block-manager] terminated");
    }

    fn handle_store_block_index(
        &self,
        hash: &bitcrab_common::types::hash::BlockHash,
        index: BlockIndex,
    ) -> Result<(), StoreError> {
        let mut write = self.backend.begin_write()?;

        let mut key = Vec::with_capacity(33);
        key.push(tables::PREFIX_BLOCK);
        key.extend_from_slice(hash.as_bytes());

        let value = bitcrab_common::wire::encode::Encoder::new()
            .encode_field(&index)
            .finish();
        write.put(tables::BLOCK_INDEX, &key, &value)?;

        // Index by header height: z + 4-byte big-endian height -> 32-byte hash
        let mut height_key = Vec::with_capacity(5);
        height_key.push(tables::PREFIX_HEADER_HEIGHT);
        height_key.extend_from_slice(&index.height.0.to_be_bytes());
        write.put(tables::CHAIN_META, &height_key, hash.as_bytes())?;

        write.commit()
    }

    fn handle_store_block_indexes(
        &self,
        indexes: Vec<(BlockHash, BlockIndex)>,
        best_tip: Option<BlockHash>,
    ) -> Result<(), StoreError> {
        let mut write = self.backend.begin_write()?;

        for (hash, index) in indexes {
            let mut key = Vec::with_capacity(33);
            key.push(tables::PREFIX_BLOCK);
            key.extend_from_slice(hash.as_bytes());
            write.put(
                tables::BLOCK_INDEX,
                &key,
                &Encoder::new().encode_field(&index).finish(),
            )?;

            let mut height_key = Vec::with_capacity(5);
            height_key.push(tables::PREFIX_HEADER_HEIGHT);
            height_key.extend_from_slice(&index.height.0.to_be_bytes());
            write.put(tables::CHAIN_META, &height_key, hash.as_bytes())?;
        }

        if let Some(hash) = best_tip {
            write.put(tables::UTXOS, &[tables::KEY_HEADERS_TIP], hash.as_bytes())?;
        }

        write.commit()
    }

    fn handle_store_header(
        &self,
        header: BlockHeader,
        height: BlockHeight,
        chain_work: bitcrab_common::types::hash::Hash256,
        is_best: bool,
    ) -> Result<(), StoreError> {
        let hash = header.block_hash();
        let index = BlockIndex {
            header: header.clone(),
            height,
            chain_work,
            file_pos: None,
            undo_pos: None,
        };

        self.handle_store_block_index(&hash, index)?;

        if is_best {
            self.handle_update_headers_tip(&hash)?;
        }

        Ok(())
    }

    async fn handle_store_blocks(
        &mut self,
        blocks: Vec<(
            BlockHeader,
            BlockHeight,
            bitcrab_common::types::hash::Hash256,
            Vec<u8>,
        )>,
    ) -> Result<Vec<FlatFilePos>, StoreError> {
        let mut entries = Vec::with_capacity(blocks.len());
        let mut positions = Vec::with_capacity(blocks.len());
        for (header, height, chain_work, raw_block) in blocks {
            let hash = header.block_hash();
            let pos = self.block_file_manager.write_block(&raw_block)?;
            positions.push(pos);
            entries.push((
                hash,
                BlockIndex {
                    header,
                    height,
                    chain_work,
                    file_pos: Some(pos),
                    undo_pos: None,
                },
            ));
        }

        // Bitcoin Core batches dirty block-index records. One storage actor
        // batch preserves flat-file ordering while avoiding a WAL commit per
        // small Signet block.
        let mut write = self.backend.begin_write()?;
        let mut highest_tip = None;
        for (hash, index) in &entries {
            let mut key = Vec::with_capacity(33);
            key.push(tables::PREFIX_BLOCK);
            key.extend_from_slice(hash.as_bytes());
            write.put(
                tables::BLOCK_INDEX,
                &key,
                &Encoder::new().encode_field(index).finish(),
            )?;

            let mut height_key = Vec::with_capacity(5);
            height_key.push(tables::PREFIX_HEADER_HEIGHT);
            height_key.extend_from_slice(&index.height.0.to_be_bytes());
            write.put(tables::CHAIN_META, &height_key, hash.as_bytes())?;

            if index.height.0 >= self.last_known_tip_height
                && highest_tip.is_none_or(|(height, _)| index.height.0 > height)
            {
                highest_tip = Some((index.height.0, *hash));
            }
        }

        // 3. Update last file in metadata
        let last_file = self.block_file_manager.current_file();
        write.put(
            tables::CHAIN_META,
            &[tables::KEY_LAST_FILE],
            &last_file.to_le_bytes(),
        )?;

        // 5. Update best full block (Block Tip) - Bitcoin Core: m_blockman.m_best_block_index
        // Memory-based Tip Tracking: skip redundant DB reads, use last_known_tip_height.
        if let Some((height, hash)) = highest_tip {
            write.put(tables::UTXOS, &[tables::KEY_BLOCK_TIP], hash.as_bytes())?;
            self.last_known_tip_height = height;
        }

        write.commit()?;
        Ok(positions)
    }

    fn handle_update_utxo_set(
        &mut self,
        coins: std::collections::HashMap<bitcrab_common::types::transaction::OutPoint, CoinUpdate>,
        best_block: Option<bitcrab_common::types::hash::BlockHash>,
        connected_blocks: Vec<(u32, bitcrab_common::types::hash::BlockHash)>,
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

        // Bitcoin Core batches dirty block-index entries with chainstate
        // flushes. Undo positions are not durability-critical before the
        // corresponding active tip is committed.
        for (hash, index) in &self.pending_undo_indexes {
            let mut key = Vec::with_capacity(33);
            key.push(tables::PREFIX_BLOCK);
            key.extend_from_slice(hash.as_bytes());
            write.put(
                tables::BLOCK_INDEX,
                &key,
                &Encoder::new().encode_field(index).finish(),
            )?;
        }

        // Atomically update height-to-hash mappings for connected blocks
        for (height, hash) in connected_blocks {
            let mut height_key = Vec::with_capacity(5);
            height_key.push(tables::PREFIX_HEIGHT);
            height_key.extend_from_slice(&height.to_be_bytes());
            write.put(tables::CHAIN_META, &height_key, hash.as_bytes())?;

            // Also keep track of tip height if this connected block is higher
            if height >= self.last_known_tip_height {
                self.last_known_tip_height = height;
            }
        }

        write.commit()?;
        self.pending_undo_indexes.clear();
        Ok(())
    }

    fn handle_store_undo(
        &mut self,
        block_hash: bitcrab_common::types::hash::BlockHash,
        undo_data: bitcrab_common::types::undo::BlockUndo,
    ) -> Result<(), StoreError> {
        let mut key = Vec::with_capacity(33);
        key.push(tables::PREFIX_BLOCK);
        key.extend_from_slice(block_hash.as_bytes());

        let mut index = if let Some(index) = self.pending_undo_indexes.get(&block_hash) {
            index.clone()
        } else {
            let read = self.backend.begin_read()?;
            let index_bytes = read.get(tables::BLOCK_INDEX, &key)?.ok_or_else(|| {
                StoreError::Custom(format!("block index missing for {block_hash}"))
            })?;
            let (index, dec) =
                BlockIndex::decode(bitcrab_common::wire::decode::Decoder::new(&index_bytes))
                    .map_err(StoreError::WireDecode)?;
            dec.finish("BlockIndex").map_err(StoreError::WireDecode)?;
            index
        };
        let block_pos = index.file_pos.ok_or_else(|| {
            StoreError::Custom(format!("block data position missing for {block_hash}"))
        })?;

        let current_size = match self.undo_sizes.get(&block_pos.file) {
            Some(size) => *size,
            None => self.block_file_manager.undo_used_size(block_pos.file)?,
        };
        let value = Encoder::new().encode_field(&undo_data).finish();
        let (undo_pos, new_size) =
            self.block_file_manager
                .write_undo(block_pos.file, &value, current_size)?;
        self.undo_sizes.insert(block_pos.file, new_size);
        index.undo_pos = Some(undo_pos);
        self.pending_undo_indexes.insert(block_hash, index);
        Ok(())
    }

    fn handle_update_active_tip(
        &self,
        hash: &bitcrab_common::types::hash::BlockHash,
    ) -> Result<(), StoreError> {
        let mut write = self.backend.begin_write()?;
        write.put(tables::UTXOS, &[tables::KEY_BEST_BLOCK], hash.as_bytes())?;
        write.commit()?;
        Ok(())
    }

    fn handle_update_headers_tip(
        &self,
        hash: &bitcrab_common::types::hash::BlockHash,
    ) -> Result<(), StoreError> {
        let mut write = self.backend.begin_write()?;
        write.put(tables::UTXOS, &[tables::KEY_HEADERS_TIP], hash.as_bytes())?;
        write.commit()?;
        Ok(())
    }

    fn handle_update_header_index(
        &self,
        hash: &bitcrab_common::types::hash::BlockHash,
        height: u32,
    ) -> Result<(), StoreError> {
        let mut write = self.backend.begin_write()?;
        let mut height_key = Vec::with_capacity(5);
        height_key.push(tables::PREFIX_HEADER_HEIGHT);
        height_key.extend_from_slice(&height.to_be_bytes());
        write.put(tables::CHAIN_META, &height_key, hash.as_bytes())?;
        write.commit()
    }

    fn handle_delete_height_mapping(&self, height: u32) -> Result<(), StoreError> {
        let mut write = self.backend.begin_write()?;
        let mut key = Vec::with_capacity(5);
        key.push(tables::PREFIX_HEIGHT);
        key.extend_from_slice(&height.to_be_bytes());
        write.delete(tables::CHAIN_META, &key)?;
        write.commit()?;
        Ok(())
    }

    fn handle_delete_block(
        &self,
        hash: &bitcrab_common::types::hash::BlockHash,
    ) -> Result<(), StoreError> {
        let mut write = self.backend.begin_write()?;

        let mut key = Vec::with_capacity(33);
        key.push(tables::PREFIX_BLOCK);
        key.extend_from_slice(hash.as_bytes());

        // We don't delete the index entry entirely, but we could clear its file_pos
        // to signal the data is missing. For now, deleting from index is simplest
        // to force a re-download/re-store.
        write.delete(tables::BLOCK_INDEX, &key)?;

        write.commit()?;
        Ok(())
    }
}

pub enum CoinUpdate {
    /// Add or update a coin in the UTXO set.
    Add(bitcrab_common::types::coin::Coin),
    /// Remove a coin (spent).
    Remove,
}
