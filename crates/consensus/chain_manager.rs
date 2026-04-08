//! ChainManager: Orchestrates the sequential validation of blocks.
//!
//! Blocks arrive via P2P out-of-order. ChainManager ensures they are
//! connected to the UTXO set in strict height order.

use crate::coins_view::{CoinsViewCache, StoreCoinsView};
use crate::validator::TransactionValidator;
use bitcrab_common::types::{block::BlockHeight, hash::BlockHash};
use bitcrab_net::p2p::actor::{Actor, ActorError, Context};
use bitcrab_storage::Store;
use std::collections::HashMap;
use tracing::{debug, info, warn};

pub enum ChainMessage {
    /// Notify that a block has been downloaded and is ready for validation.
    BlockDownloaded(BlockHash, BlockHeight),
    /// Trigger an attempt to advance the chain tip.
    Advance,
}

pub struct ChainManager {
    store: Store,
    /// Blocks that have been downloaded but are waiting for their predecessor.
    waiting_blocks: HashMap<BlockHeight, BlockHash>,
}

impl ChainManager {
    pub fn new(store: Store) -> Self {
        Self {
            store,
            waiting_blocks: HashMap::new(),
        }
    }

    /// Attempt to connect as many sequential blocks as possible.
    async fn drain_queue(&mut self) -> Result<(), ActorError> {
        loop {
            // 1. Determine the next height we need
            let current_hash = self
                .store
                .get_best_block()
                .map_err(|e| ActorError::Internal(e.to_string()))?;

            let current_height = if let Some(hash) = current_hash {
                self.store
                    .get_block_index(&hash)
                    .map_err(|e| ActorError::Internal(e.to_string()))?
                    .map(|idx| idx.height)
                    .unwrap_or(BlockHeight(0))
            } else {
                BlockHeight(0)
            };

            let next_height = BlockHeight(current_height.0 + 1);

            // 2. Check if we have the next block in our waiting list
            let Some(hash) = self.waiting_blocks.remove(&next_height) else {
                break;
            };

            // 3. Fetch block from storage
            let Some(raw_block_bytes) = self
                .store
                .get_block(&hash)
                .map_err(|e| ActorError::Internal(e.to_string()))?
            else {
                warn!(
                    "[chain-manager] block data missing for hash {}. re-downloading...",
                    hash
                );
                break;
            };

            // 4. Decode block
            use bitcrab_common::wire::decode::{BitcoinDecode, Decoder};
            let (block, _) =
                bitcrab_common::types::block::Block::decode(Decoder::new(&raw_block_bytes))
                    .map_err(|e| ActorError::Internal(format!("failed to decode block: {}", e)))?;

            // 5. Process block (Consensus Validation + UTXO update)
            info!(
                "[chain-manager] attempting to connect block {} at height {}",
                hash, next_height
            );

            // Validation logic (inline process_block logic to avoid Node dependency)
            let base_view = StoreCoinsView::new(self.store.clone());
            let mut cache_view = CoinsViewCache::new(base_view);

            match TransactionValidator::connect_block(&block, next_height, &mut cache_view) {
                Ok((_fees, undo)) => {
                    // Store undo data
                    self.store
                        .store_undo(hash, undo)
                        .await
                        .map_err(|e| ActorError::Internal(e.to_string()))?;

                    // Flush UTXO changes
                    let store_view = StoreCoinsView::new(self.store.clone());
                    store_view
                        .flush(&cache_view)
                        .await
                        .map_err(|e| ActorError::Internal(e.to_string()))?;

                    info!("[chain-manager] successfully connected block {}", hash);
                }
                Err(e) => {
                    warn!("[chain-manager] consensus failed for block {}: {}", hash, e);
                    break;
                }
            }
        }
        Ok(())
    }
}

impl Actor for ChainManager {
    type Message = ChainMessage;

    fn on_start(
        &mut self,
        ctx: &mut Context<Self>,
    ) -> impl std::future::Future<Output = Result<(), ActorError>> + Send {
        let _handle = ctx.handle();
        async move {
            info!("[chain-manager] starting chain state manager");
            Ok(())
        }
    }

    fn handle(
        &mut self,
        msg: Self::Message,
        _ctx: &mut Context<Self>,
    ) -> impl std::future::Future<Output = Result<(), ActorError>> + Send {
        async move {
            match msg {
                ChainMessage::BlockDownloaded(hash, height) => {
                    debug!(
                        "[chain-manager] block {} downloaded at height {}",
                        hash, height
                    );
                    self.waiting_blocks.insert(height, hash);
                    self.drain_queue().await?;
                }
                ChainMessage::Advance => {
                    self.drain_queue().await?;
                }
            }
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bitcrab_common::types::{
        amount::Amount,
        block::{Block, BlockHeader, BlockHeight},
        hash::{BlockHash, Hash256},
        transaction::{OutPoint, Transaction, TxIn, TxOut},
    };
    use bitcrab_common::wire::encode::{BitcoinEncode, Encoder};
    use bitcrab_net::p2p::message::Magic;
    use bitcrab_storage::Store;

    fn create_block(prev_hash: BlockHash, height: u32, txs: Vec<Transaction>) -> Block {
        let mut header = BlockHeader {
            version: 1,
            prev_hash,
            merkle_root: Hash256::zero(),
            time: 1_700_000_000 + (height * 600),
            bits: 0x1d00ffff,
            nonce: 0,
        };
        let block_without_root = Block::new(header.clone(), txs);
        header.merkle_root = block_without_root.compute_merkle_root();
        Block::new(header, block_without_root.transactions)
    }

    fn create_coinbase() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_out: OutPoint {
                    txid: Hash256::zero().into(),
                    vout: 0xffff_ffff,
                },
                script_sig: vec![],
                sequence: 0xffff_ffff,
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50_000_000_00),
                script_pubkey: vec![],
            }],
            lock_time: 0,
        }
    }

    #[tokio::test]
    async fn test_sequential_drain() {
        let store = Store::in_memory(Magic::Regtest).unwrap();

        let b0 = create_block(BlockHash::zero(), 0, vec![create_coinbase()]);
        let b1 = create_block(b0.header.block_hash(), 1, vec![create_coinbase()]);

        // 1. Index headers
        store
            .store_header(b0.header.clone(), BlockHeight(0), false)
            .unwrap();
        store
            .store_header(b1.header.clone(), BlockHeight(1), true)
            .unwrap();

        // 2. Setup ChainManager
        let mut manager = ChainManager::new(store.clone());

        // 3. Receive b1 (out of order)
        let raw1 = b1.encode(Encoder::new()).finish();
        store
            .store_block(b1.header.clone(), BlockHeight(1), raw1)
            .await
            .unwrap();
        manager
            .waiting_blocks
            .insert(BlockHeight(1), b1.header.block_hash());

        manager.drain_queue().await.unwrap();
        assert!(store.get_best_block().unwrap().is_none());

        // 4. Receive b0 (fills the gap)
        let raw0 = b0.encode(Encoder::new()).finish();
        store
            .store_block(b0.header.clone(), BlockHeight(0), raw0)
            .await
            .unwrap();
        manager
            .waiting_blocks
            .insert(BlockHeight(0), b0.header.block_hash());

        manager.drain_queue().await.unwrap();

        // Hashes should match
        assert_eq!(
            store.get_best_block().unwrap(),
            Some(b1.header.block_hash())
        );
    }
}
