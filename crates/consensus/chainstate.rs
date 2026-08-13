//! ChainManager: Orchestrates the sequential validation of blocks.
//!
//! Blocks arrive via P2P out-of-order. ChainManager ensures they are
//! connected to the UTXO set in strict height order.

use crate::coins::{CoinsView, CoinsViewCache, StoreCoinsView};
use crate::engine::ConsensusEngine;
use crate::pow::BlockIndexProvider;
use crate::validation::{TransactionValidator, ValidationError};
use bitcrab_common::types::block::{BlockHeight, BlockIndex};
use bitcrab_common::types::hash::{BlockHash, Hash256};
use bitcrab_common::{ChainParams, ChainType};
use bitcrab_storage::Store;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

/// Messages sent to the Chainstate Actor.
#[allow(clippy::large_enum_variant)]
pub enum ChainstateMsg {
    /// Process a new block header.
    ProcessHeader {
        header: bitcrab_common::types::block::BlockHeader,
        height: BlockHeight,
        reply_to: oneshot::Sender<Result<(), String>>,
    },
    /// Persist an already validated header batch.
    ProcessHeaders {
        indexes: Vec<(BlockHash, BlockIndex)>,
        best_tip: Option<BlockHash>,
        reply_to: oneshot::Sender<Result<(), String>>,
    },
    /// Notify that a block data has been downloaded.
    ProcessBlockDownloaded {
        hash: BlockHash,
        height: BlockHeight,
        reply_to: oneshot::Sender<Result<(), String>>,
    },
    /// Attempt to connect all sequential blocks on disk to the tip.
    ActivateBestChain {
        reply_to: oneshot::Sender<Result<(), String>>,
    },
    /// Load genesis block.
    LoadGenesis {
        params: ChainParams,
        reply_to: oneshot::Sender<Result<(), String>>,
    },
}

/// A handle to the Chainstate Actor that can be shared across tasks.
#[derive(Clone)]
pub struct ChainstateHandle {
    tx: mpsc::Sender<ChainstateMsg>,
    active_tip: Arc<RwLock<Option<(BlockHash, u32)>>>,
}

impl ChainstateHandle {
    pub fn new(tx: mpsc::Sender<ChainstateMsg>) -> Self {
        Self {
            tx,
            active_tip: Arc::new(RwLock::new(None)),
        }
    }

    pub fn active_tip_state(&self) -> Arc<RwLock<Option<(BlockHash, u32)>>> {
        self.active_tip.clone()
    }

    pub fn active_tip(&self) -> Option<(BlockHash, u32)> {
        *self.active_tip.read().unwrap()
    }

    pub async fn process_header(
        &self,
        header: bitcrab_common::types::block::BlockHeader,
        height: BlockHeight,
    ) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(ChainstateMsg::ProcessHeader {
                header,
                height,
                reply_to: tx,
            })
            .await
            .map_err(|_| "Chainstate Actor dead".to_string())?;
        rx.await
            .map_err(|_| "Chainstate Actor dropped response".to_string())?
    }

    pub async fn process_block_downloaded(
        &self,
        hash: BlockHash,
        height: BlockHeight,
    ) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(ChainstateMsg::ProcessBlockDownloaded {
                hash,
                height,
                reply_to: tx,
            })
            .await
            .map_err(|_| "Chainstate Actor dead".to_string())?;
        rx.await
            .map_err(|_| "Chainstate Actor dropped response".to_string())?
    }

    pub async fn process_headers(
        &self,
        indexes: Vec<(BlockHash, BlockIndex)>,
        best_tip: Option<BlockHash>,
    ) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(ChainstateMsg::ProcessHeaders {
                indexes,
                best_tip,
                reply_to: tx,
            })
            .await
            .map_err(|_| "Chainstate Actor dead".to_string())?;
        rx.await
            .map_err(|_| "Chainstate Actor dropped response".to_string())?
    }

    pub async fn activate_best_chain(&self) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(ChainstateMsg::ActivateBestChain { reply_to: tx })
            .await
            .map_err(|_| "Chainstate Actor dead".to_string())?;
        rx.await
            .map_err(|_| "Chainstate Actor dropped response".to_string())?
    }

    pub async fn load_genesis(&self, params: ChainParams) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(ChainstateMsg::LoadGenesis {
                params,
                reply_to: tx,
            })
            .await
            .map_err(|_| "Chainstate Actor dead".to_string())?;
        rx.await
            .map_err(|_| "Chainstate Actor dropped response".to_string())?
    }
}

/// Bitcoin Core: `Chainstate` in `src/validation.h`
///
/// Manages the sequential validation and connection of blocks to the UTXO set.
pub struct ChainstateManager {
    store: Store,
    chain: ChainType,
    /// Blocks that have been downloaded but are waiting for their predecessor.
    waiting_blocks: HashMap<BlockHeight, BlockHash>,
    /// Prevents re-entrant ActivateBestChain calls.
    is_activating: bool,
    /// Persistent UTXO cache to match Bitcoin Core's `m_view`.
    cache_view: CoinsViewCache<StoreCoinsView>,
    /// Blocks connected since last disk flush.
    blocks_since_flush: u32,
    /// Bitcoin Core's active `CChain` tip, independent from coins DB flushes.
    active_tip: Arc<RwLock<Option<(BlockHash, u32)>>>,
    engine: ConsensusEngine,
    script_checks: bool,
    last_failed_activation: Option<(BlockHeight, BlockHash, Instant)>,
}

/// Bitcoin Core: `FlushStateMode` in `src/validation.cpp`
const FLUSH_INTERVAL_BLOCKS: u32 = 1024;

impl BlockIndexProvider for ChainstateManager {
    fn get_block_index_by_height(&self, height: u32) -> Option<BlockIndex> {
        self.store.get_block_index_by_height(height)
    }
}

impl BlockIndexProvider for Store {
    fn get_block_index_by_height(&self, height: u32) -> Option<BlockIndex> {
        // 1. Try main chain index first (Fully validated blocks)
        if let Ok(Some(hash)) = self.get_block_hash(height) {
            if let Ok(Some(index)) = self.get_block_index(&hash) {
                return Some(index);
            }
        }

        // 2. Fallback to header index (Headers-first sync)
        if let Ok(Some(hash)) = self.get_block_hash_by_header_height(height) {
            if let Ok(Some(index)) = self.get_block_index(&hash) {
                return Some(index);
            }
        }

        None
    }
}

impl ChainstateManager {
    pub fn new(
        store: Store,
        chain: ChainType,
        active_tip: Arc<RwLock<Option<(BlockHash, u32)>>>,
        dbcache_bytes: usize,
        engine: ConsensusEngine,
        script_checks: bool,
    ) -> Self {
        let b_view = StoreCoinsView::new(store.clone());
        let cache_view = CoinsViewCache::new(b_view, dbcache_bytes.saturating_mul(3) / 4);
        let persisted_tip = store.get_best_block().ok().flatten().and_then(|hash| {
            store
                .get_block_index(&hash)
                .ok()
                .flatten()
                .map(|index| (hash, index.height.0))
        });
        *active_tip.write().unwrap() = persisted_tip;

        Self {
            store,
            chain,
            waiting_blocks: HashMap::new(),
            is_activating: false,
            cache_view,
            blocks_since_flush: 0,
            active_tip,
            engine,
            script_checks,
            last_failed_activation: None,
        }
    }

    pub fn params(&self) -> ChainParams {
        self.chain.chain_params()
    }

    /// Verifies and potentially repairs the chain tips on startup.
    ///
    /// If the header tip is on an orphan branch or excessively far from blocks,
    /// we reset it to allow synchronization to resume correctly.
    pub async fn verify_and_repair_tips(&mut self) -> Result<(), String> {
        let header_tip_hash = self.store.get_headers_tip().map_err(|e| e.to_string())?;
        let validated_tip_hash = self.store.get_best_block().map_err(|e| e.to_string())?;

        let header_index = if let Some(ref h) = header_tip_hash {
            self.store.get_block_index(h).map_err(|e| e.to_string())?
        } else {
            None
        };

        let validated_index = if let Some(ref h) = validated_tip_hash {
            self.store.get_block_index(h).map_err(|e| e.to_string())?
        } else {
            None
        };

        let header_height = header_index.as_ref().map(|i| i.height.0).unwrap_or(0);
        let validated_height = validated_index.as_ref().map(|i| i.height.0).unwrap_or(0);
        let header_work = header_index
            .as_ref()
            .map(|i| i.chain_work)
            .unwrap_or(Hash256::zero());

        info!(
            "[chainstate] startup check: headers at {} (work: {}), validated blocks at {}",
            header_height, header_work, validated_height
        );

        // 1. Detect lagging header tip (Forward Scan)
        let mut scout_height = header_height + 1;
        let mut highest_header_found = None;
        let mut current_best_work = header_work;

        while let Ok(Some(hash)) = self.store.get_block_hash(scout_height) {
            if let Ok(Some(index)) = self.store.get_block_index(&hash) {
                if index.chain_work > current_best_work {
                    highest_header_found = Some(hash);
                    current_best_work = index.chain_work;
                }
            }
            scout_height += 1;
            if scout_height > header_height + 500000 {
                break;
            }
        }

        if let Some(hash) = highest_header_found {
            info!("[chainstate] Found better indexed headers ahead! Advancing headers tip.");
            self.store
                .update_headers_tip(hash)
                .await
                .map_err(|e| e.to_string())?;
        }

        // 2. Ensure headers are at least as advanced as validated blocks
        if header_height < validated_height {
            if let Some(hash) = validated_tip_hash {
                info!(
                    "[chainstate] Header tip behind validated blocks ({} < {}). Aligning headers.",
                    header_height, validated_height
                );
                self.store
                    .update_headers_tip(hash)
                    .await
                    .map_err(|e| e.to_string())?;
            }
        }

        // 3. Detect orphan/stall: Only reset if headers are INSANELY far (corruption check)
        if header_height > validated_height + 2000000 {
            warn!("[chainstate] Headers are suspiciously far from blocks ({} vs {}). Resetting head to validated tip for safety.", header_height, validated_height);
            if let Some(hash) = validated_tip_hash {
                self.store
                    .update_headers_tip(hash)
                    .await
                    .map_err(|e| e.to_string())?;
            }
        }

        Ok(())
    }

    /// Process a new block header sequentially.
    pub async fn process_header(
        &mut self,
        header: bitcrab_common::types::block::BlockHeader,
        height: BlockHeight,
    ) -> Result<(), String> {
        let hash = header.block_hash();

        // 0. Atomic check: skip if we already stored this header
        if self
            .store
            .get_block_index(&hash)
            .map_err(|e| e.to_string())?
            .is_some()
        {
            return Ok(());
        }

        let prev_hash = header.prev_hash;

        // 1. Calculate cumulative work
        let prev_work = if prev_hash.is_zero() {
            Hash256::zero()
        } else {
            self.store
                .get_block_index(&prev_hash)
                .map_err(|e| e.to_string())?
                .map(|i| i.chain_work)
                .unwrap_or(Hash256::zero())
        };

        let block_work = crate::pow::calculate_block_work(header.bits);
        let chain_work = crate::pow::add_chain_work(prev_work, block_work);

        debug!(
            "[chainstate] actor committing header {} at height {} (work: {})",
            hash, height, chain_work
        );

        // 2. Store the header in the block index
        let index = BlockIndex {
            header,
            height,
            chain_work,
            file_pos: None,
            undo_pos: None,
        };
        self.store
            .store_block_index(&hash, index)
            .await
            .map_err(|e| e.to_string())?;

        // 3. Atomically update the best headers tip ONLY if it's the most work
        let current_headers_tip = self.store.get_headers_tip().map_err(|e| e.to_string())?;
        let current_work = if let Some(tip_hash) = current_headers_tip {
            self.store
                .get_block_index(&tip_hash)
                .map_err(|e| e.to_string())?
                .map(|i| i.chain_work)
                .unwrap_or(Hash256::zero())
        } else {
            Hash256::zero()
        };

        debug!(
            "[chainstate] comparing work for header {}: current_tip_work={}, new_header_work={}",
            hash, current_work, chain_work
        );

        if chain_work > current_work {
            self.store
                .update_headers_tip(hash)
                .await
                .map_err(|e| e.to_string())?;
            debug!(
                "[chainstate] best header tip advanced: height {} (work: {}, hash: {})",
                height.0, chain_work, hash
            );
        } else {
            debug!(
                "[chainstate] header {} at height {} did not advance tip (work: {} <= current: {})",
                hash, height.0, chain_work, current_work
            );
        }

        Ok(())
    }

    /// Notify that a block has been downloaded and is ready for validation.
    ///
    /// Bitcoin Core: `AcceptBlock()` stores the block and updates BLOCK_HAVE_DATA.
    /// It does NOT call ActivateBestChain — that's done separately by ProcessNewBlock.
    /// In our actor model, the connector task calls activate_best_chain periodically.
    pub async fn process_block_downloaded(
        &mut self,
        hash: BlockHash,
        height: BlockHeight,
    ) -> Result<(), String> {
        debug!(
            "[chainstate-manager] block {} downloaded at height {}",
            hash, height
        );
        self.waiting_blocks.insert(height, hash);
        // Bitcoin Core: AcceptBlock does NOT call ActivateBestChain.
        // The connector task (equivalent to ProcessNewBlock's final step) handles activation.
        Ok(())
    }

    /// Attempt to connect as many sequential blocks as possible to the tip.
    ///
    /// Bitcoin Core: `Chainstate::ActivateBestChain()` in `src/validation.cpp`
    ///
    /// Key design decisions matching Core:
    /// - Mutual exclusion via `is_activating` flag (Core uses `m_chainstate_mutex`)
    /// - Loops until tip == most-work-chain (Core's `do-while` loop)
    /// - Periodic flush to disk (Core: `FlushStateToDisk(PERIODIC)`)
    /// - Per-block ConnectTip → ConnectBlock → view.Flush cycle
    pub async fn activate_best_chain(&mut self) -> Result<(), String> {
        // Bitcoin Core: LOCK(m_chainstate_mutex) — mutual exclusion
        if self.is_activating {
            return Ok(());
        }
        self.is_activating = true;

        let result = self.activate_best_chain_inner().await;

        self.is_activating = false;
        result
    }

    /// Inner implementation of ActivateBestChain.
    async fn activate_best_chain_inner(&mut self) -> Result<(), String> {
        let mut total_connected: u32 = 0;
        const ACTIVATE_BATCH_SIZE: u32 = 128;

        // Bitcoin Core: `-assumevalid` names a block *hash*; script checks are
        // skipped for everything at or below it. Resolve that hash to a height
        // through the block index rather than hardcoding a per-network height —
        // the hash already lives in `ConsensusParams`, and having a second copy
        // here is how the two silently drift apart.
        //
        // An unknown hash yields `None`, which means full script verification.
        // Failing towards more checking is the only safe direction.
        let assume_valid_height = {
            let assume_valid = self.params().consensus.default_assume_valid;
            if assume_valid.is_zero() {
                None
            } else {
                self.store
                    .get_block_index(&assume_valid)
                    .map_err(|e| e.to_string())?
                    .map(|index| index.height.0)
            }
        };

        // 1. Initial State: Load current tip from cache first (latest state), fallback to store disk
        let mut current_tip = if let Some(tip_hash) =
            self.cache_view
                .get_best_block()
                .or(self.store.get_best_block().ok().flatten())
        {
            self.store
                .get_block_index(&tip_hash)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("Current tip block index missing for hash {}", tip_hash))?
        } else {
            // No tip yet? Fallback to genesis
            let gen_hash = self.params().genesis_hash();
            self.store
                .get_block_index(&gen_hash)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("Genesis block index missing for hash {}", gen_hash))?
        };

        loop {
            if total_connected >= ACTIVATE_BATCH_SIZE {
                debug!(
                    "[chainstate] reached activation batch limit ({}), returning to actor loop",
                    ACTIVATE_BATCH_SIZE
                );
                break;
            }

            // Allow other actor messages (like RPC) to be processed
            tokio::task::yield_now().await;

            // 2. Identify Next Block using local tracking
            let next_height = BlockHeight(current_tip.height.0 + 1);
            let index_prev = current_tip.clone();

            let hash_opt = if let Some(hash) = self.waiting_blocks.remove(&next_height) {
                info!(
                    "[chainstate] activation: found block {} at height {} in RAM (waiting_blocks)",
                    hash, next_height
                );
                Some(hash)
            } else {
                let h_hash = self.store.get_block_hash(next_height.0).ok().flatten();
                let z_hash = self
                    .store
                    .get_block_hash_by_header_height(next_height.0)
                    .ok()
                    .flatten();

                if h_hash.is_none() && z_hash.is_none() {
                    if next_height.0 < 500 || next_height.0 % 1000 == 0 {
                        info!("[chainstate] activation: MISSING hash for height {} (checked H and z tables)", next_height);
                    }
                    None
                } else {
                    h_hash.or(z_hash)
                }
            };

            let Some(hash) = hash_opt else {
                break;
            };

            if self.last_failed_activation.as_ref().is_some_and(
                |(height, failed_hash, failed_at)| {
                    *height == next_height
                        && *failed_hash == hash
                        && failed_at.elapsed() < Duration::from_secs(30)
                },
            ) {
                break;
            }

            let block_data_opt = self.store.get_block(&hash).map_err(|e| e.to_string())?;
            if block_data_opt.is_none() {
                info!("[chainstate] activation: block data MISSING from disk for hash {} at height {}", hash, next_height);
                break;
            }

            let raw_block_bytes = block_data_opt.unwrap();
            use bitcrab_common::wire::decode::{BitcoinDecode, Decoder};
            let (block, _) =
                bitcrab_common::types::block::Block::decode(Decoder::new(&raw_block_bytes))
                    .map_err(|e| format!("failed to decode block: {}", e))?;

            let params = self.params();
            match TransactionValidator::connect_block(
                &block,
                next_height,
                &index_prev,
                &mut self.cache_view,
                &params,
                &self.store,
                self.script_checks
                    && assume_valid_height.map_or(true, |height| next_height.0 > height),
                self.engine,
            )
            .await
            {
                Ok((_fees, undo)) => {
                    self.last_failed_activation = None;
                    self.store
                        .store_undo(hash, undo)
                        .await
                        .map_err(|e| e.to_string())?;

                    self.cache_view.set_best_block(hash, next_height.0);
                    *self.active_tip.write().unwrap() = Some((hash, next_height.0));

                    self.blocks_since_flush += 1;
                    total_connected += 1;

                    // 3. Update local tip tracking
                    current_tip = BlockIndex {
                        header: block.header.clone(),
                        height: next_height,
                        chain_work: crate::pow::add_chain_work(
                            index_prev.chain_work,
                            crate::pow::calculate_block_work(block.header.bits),
                        ),
                        file_pos: None, // Not strictly needed for ConnectTip
                        undo_pos: None,
                    };

                    debug!("[chainstate] ActivateBestChain: connected block {} at height {} (batch count: {})", hash, next_height.0, total_connected);

                    if self.blocks_since_flush >= FLUSH_INTERVAL_BLOCKS {
                        let (hits, misses) = self.cache_view.cache_stats();
                        info!(
                            "[chainstate] FlushStateToDisk at height {}: cache_entries={}, hits={}, misses={}",
                            next_height,
                            self.cache_view.cache_len(),
                            hits,
                            misses
                        );
                        let store_view = StoreCoinsView::new(self.store.clone());
                        store_view
                            .flush(&mut self.cache_view)
                            .await
                            .map_err(|e| e.to_string())?;
                        self.blocks_since_flush = 0;
                    }

                    if next_height.0 % 256 == 0 {
                        info!("*** Chainstate progress: height {} ***", next_height.0);
                    }
                }
                Err(e) => {
                    // Detailed diagnostics: check if coin is in cache or store
                    if let ValidationError::InputMissingOrSpent(ref op) = e {
                        let in_store = self.store.get_coin(op).ok().flatten().is_some();
                        let cache_size = self.cache_view.cache_len();
                        warn!("[chainstate] CONSENSUS FAILED at height {} (block {}): {}\n  -> coin in store: {}, cache entries: {}, blocks_since_flush: {}",
                            next_height, hash, e, in_store, cache_size, self.blocks_since_flush);
                    } else {
                        warn!(
                            "[chainstate] CONSENSUS FAILED at height {} (block {}): {}",
                            next_height, hash, e
                        );
                    }
                    self.last_failed_activation = Some((next_height, hash, Instant::now()));
                    break;
                }
            }
        }

        if total_connected > 0 {
            debug!(
                "[chainstate] ActivateBestChain connected {} blocks",
                total_connected
            );
        }

        Ok(())
    }

    /// Ensures the genesis block is present in the block index.
    pub async fn load_genesis_block(&mut self, params: &ChainParams) -> Result<(), String> {
        let hash = params.genesis_hash();

        // 1. Check if already initialized
        match self
            .store
            .get_block_index(&hash)
            .map_err(|e| e.to_string())?
        {
            Some(_) => {
                debug!("[chainstate] genesis block already initialized: {}", hash);
                Ok(())
            }
            None => {
                info!(
                    "[chainstate] initializing genesis block for network {:?}: {}",
                    self.params().magic,
                    hash
                );

                let work = crate::pow::calculate_block_work(params.genesis_header.bits);

                // 2. Write genesis header to height 0 and mark as best block (tip)
                let index = BlockIndex {
                    header: params.genesis_header.clone(),
                    height: bitcrab_common::types::block::BlockHeight(0),
                    chain_work: work,
                    file_pos: None,
                    undo_pos: None,
                };

                self.store
                    .store_block_index(&hash, index)
                    .await
                    .map_err(|e| e.to_string())?;
                self.store
                    .update_headers_tip(hash)
                    .await
                    .map_err(|e| e.to_string())?;

                // CRITICAL: Ensure Genesis (height 0) is indexed in both 'H' (connected) and 'z' (headers) tables
                // and mark as the Active Tip. This prevents "out of range" errors during early sync.
                self.store
                    .store_header_index_only(hash, 0)
                    .await
                    .map_err(|e| e.to_string())?;
                self.store
                    .update_active_tip(hash)
                    .await
                    .map_err(|e| e.to_string())?;
                self.cache_view.set_best_block(hash, 0);
                *self.active_tip.write().unwrap() = Some((hash, 0));

                info!(
                    "[chainstate] genesis block successfully loaded (work: {})",
                    work
                );
                Ok(())
            }
        }
    }
}

/// The main loop for the Chainstate Actor.
pub async fn run_chainstate_loop(
    mut manager: ChainstateManager,
    mut rx: mpsc::Receiver<ChainstateMsg>,
) {
    info!("[chainstate-actor] started");

    // Perform self-healing on startup
    if let Err(e) = manager.verify_and_repair_tips().await {
        warn!("[chainstate-actor] self-healing failed: {}", e);
    }

    while let Some(msg) = rx.recv().await {
        match msg {
            ChainstateMsg::ProcessHeader {
                header,
                height,
                reply_to,
            } => {
                let res = manager.process_header(header, height).await;
                let _ = reply_to.send(res);
            }
            ChainstateMsg::ProcessBlockDownloaded {
                hash,
                height,
                reply_to,
            } => {
                let res = manager.process_block_downloaded(hash, height).await;
                let _ = reply_to.send(res);
            }
            ChainstateMsg::ProcessHeaders {
                indexes,
                best_tip,
                reply_to,
            } => {
                let res = manager
                    .store
                    .store_block_indexes(indexes, best_tip)
                    .await
                    .map_err(|e| e.to_string());
                let _ = reply_to.send(res);
            }
            ChainstateMsg::ActivateBestChain { reply_to } => {
                let res = manager.activate_best_chain().await;
                let _ = reply_to.send(res);
            }
            ChainstateMsg::LoadGenesis { params, reply_to } => {
                let res = manager.load_genesis_block(&params).await;
                let _ = reply_to.send(res);
            }
        }
    }

    info!("[chainstate-actor] stopped");
}
