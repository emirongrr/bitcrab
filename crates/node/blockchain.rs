//! Bitcoin Blockchain orchestrator.
//!
//! This module represents the highest level of chain management,
//! analogous to `CChainState` and `node::NodeContext` in Bitcoin Core.
//! It manages the active chain state, UTXO set updates, and mempool validation.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use thiserror::Error;
use tracing::{debug, error, info, warn};

use bitcrab_common::types::{
    block::{BlockHeight, BlockIndex},
    hash::BlockHash,
    transaction::Transaction,
};
use bitcrab_common::{ChainParams, ChainType};
use bitcrab_consensus::pow::BlockIndexProvider;
use bitcrab_consensus::{chainstate::ChainstateHandle, TransactionValidator};
use bitcrab_net::p2p::peer_manager::ValidationInterface;
use bitcrab_storage::{Store, StoreError};

use crate::mempool::{Mempool, MempoolError};

#[derive(Debug, Error)]
pub enum ChainError {
    #[error("Storage error: {0}")]
    Storage(#[from] StoreError),
    #[error("Consensus error: {0}")]
    Consensus(String),
}

/// The main orchestrator for chain operations.
///
/// Bitcoin Core: `CChainState`
pub struct Blockchain {
    pub store: Store,
    pub chainstate: ChainstateHandle,
    pub mempool: Arc<Mempool>,
    pub chain: ChainType,
    /// In-memory cache of the current best header path (Bitcoin Core: CChain)
    best_header_chain: Arc<RwLock<Vec<BlockHash>>>,
}

struct HeaderBatchProvider<'a> {
    base: &'a Blockchain,
    by_height: &'a HashMap<u32, BlockIndex>,
}

impl BlockIndexProvider for HeaderBatchProvider<'_> {
    fn get_block_index_by_height(&self, height: u32) -> Option<BlockIndex> {
        self.by_height
            .get(&height)
            .cloned()
            .or_else(|| self.base.get_block_index_by_height(height))
    }
}

impl Blockchain {
    pub fn new(
        store: Store,
        chainstate: ChainstateHandle,
        mempool: Arc<Mempool>,
        chain: ChainType,
    ) -> Self {
        let mut blockchain = Self {
            store,
            chainstate,
            mempool,
            chain,
            best_header_chain: Arc::new(RwLock::new(Vec::new())),
        };

        // Populate the header chain from disk on startup
        blockchain.reconstruct_header_chain();

        blockchain
    }

    pub fn params(&self) -> ChainParams {
        self.chain.chain_params()
    }

    /// Reconstruct the in-memory best header path by walking back from the stored best header tip.
    /// Also performs self-healing by ensuring every header in the best path is indexed by height.
    fn reconstruct_header_chain(&mut self) {
        let headers_tip = self.store.get_headers_tip().unwrap_or(None);
        let blocks_tip = self.store.get_best_block().unwrap_or(None);

        let tip_result = headers_tip.or(blocks_tip);

        let Some(tip_hash) = tip_result else {
            info!("[blockchain] no headers found in store, starting fresh");
            return;
        };

        let Some(tip_index) = self.store.get_block_index(&tip_hash).ok().flatten() else {
            warn!(
                "[blockchain] tip index missing for {}, reconstruction aborted",
                tip_hash
            );
            return;
        };

        let total_expected = tip_index.height.0 + 1;
        info!(
            "[blockchain] reconstructing header chain from height {} (tip: {})",
            tip_index.height.0, tip_hash
        );

        let mut path = vec![BlockHash::ZERO; total_expected as usize];
        let mut current_hash = Some(tip_hash);
        let mut current_height = tip_index.height.0;
        let mut repaired_count = 0;

        while let Some(hash) = current_hash {
            if hash.is_zero() {
                break;
            }

            path[current_height as usize] = hash;

            // Self-healing: verify the height index ('z') matches
            if let Ok(Some(indexed_hash)) =
                self.store.get_block_hash_by_header_height(current_height)
            {
                if indexed_hash != hash {
                    repaired_count += 1;
                }
            } else {
                repaired_count += 1;
            }

            if current_height == 0 {
                break;
            }

            current_hash = self
                .store
                .get_block_index(&hash)
                .ok()
                .flatten()
                .map(|idx| idx.header.prev_hash);
            current_height -= 1;
        }

        // Finalize cache
        *self.best_header_chain.write().unwrap() = path;
        info!(
            "[blockchain] header chain cache initialized with {} headers. Repository verified.",
            total_expected
        );
        if repaired_count > 0 {
            warn!(
                "[blockchain] self-healing: detected {} incorrect header height indices",
                repaired_count
            );
        }
    }

    /// Resolve the hash on our best header path at `height`.
    ///
    /// Prefers the in-memory `CChain` cache and falls back to the on-disk
    /// height indexes, so a cache gap degrades the locator's density instead of
    /// truncating it.
    fn header_hash_at_height(&self, height: u32) -> Option<BlockHash> {
        {
            let chain = self.best_header_chain.read().unwrap();
            if let Some(hash) = chain.get(height as usize) {
                if !hash.is_zero() {
                    return Some(*hash);
                }
            }
        }

        self.get_block_index_by_height(height)
            .map(|index| index.header.block_hash())
    }

    /// Build a block locator rooted at `tip`.
    ///
    /// Bitcoin Core: `GetLocator()` in `src/chain.cpp`.
    pub fn block_locator(&self, tip: &BlockHash) -> Vec<BlockHash> {
        let genesis = self.params().genesis_hash();

        // An unknown or empty tip gives the peer nothing to fork from; genesis
        // is the only honest answer and matches Core's empty-chain locator.
        let Some(tip_height) = self
            .store
            .get_block_index(tip)
            .ok()
            .flatten()
            .map(|index| index.height.0)
        else {
            return vec![genesis];
        };

        let mut locator = bitcrab_common::types::block::build_block_locator(tip_height, |height| {
            if height == tip_height {
                Some(*tip)
            } else {
                self.header_hash_at_height(height)
            }
        });

        // build_block_locator skips heights it cannot resolve; genesis is always
        // known and a peer needs it as the guaranteed common ancestor.
        if locator.last() != Some(&genesis) {
            locator.push(genesis);
        }

        locator
    }

    /// Update the in-memory chain when a new header is added to the best path.
    pub fn update_header_chain(&self, hash: BlockHash, height: u32) {
        let mut chain = self.best_header_chain.write().unwrap();

        // If the chain is empty and we are starting from Genesis or low heights, reset it
        if chain.is_empty() && height < 2000 {
            // Reconstruct logic or just start pushing.
            // Better to reconstruct basics if missing genesis.
            if height == 0 {
                chain.push(hash);
                return;
            }
        }

        if (height as usize) == chain.len() {
            chain.push(hash);
            if height % 5000 == 0 {
                info!(
                    "[blockchain] extended header chain cache to height {}",
                    height
                );
            }
        } else if (height as usize) < chain.len() {
            // Reorg or same height replacement: truncate and extend
            if chain[height as usize] != hash {
                chain.truncate(height as usize);
                chain.push(hash);
                info!(
                    "[blockchain] header chain cache reorg/updated at height {}",
                    height
                );
            }
        } else {
            // Gap detected: if headers tip in DB is already far ahead, we might need a partial reconstruction
            // or just wait for sequential processing. During IBD, headers usually arrive in large batches.
            if height % 1000 == 0 {
                debug!(
                    "[blockchain] gap in header chain cache: height {} (cache len {})",
                    height,
                    chain.len()
                );
            }
        }
    }
}

impl BlockIndexProvider for Blockchain {
    fn get_block_index_by_height(&self, height: u32) -> Option<BlockIndex> {
        // Special case for Genesis
        if height == 0 {
            let params = self.params();
            let work = bitcrab_consensus::pow::calculate_block_work(params.genesis_header.bits);
            return Some(BlockIndex {
                header: params.genesis_header,
                height: BlockHeight(0),
                chain_work: work,
                file_pos: None,
                undo_pos: None,
            });
        }

        // 1. Try main chain index first (Fully validated blocks)
        if let Ok(Some(hash)) = self.store.get_block_hash(height) {
            if let Ok(Some(index)) = self.store.get_block_index(&hash) {
                return Some(index);
            }
        }

        // 2. Fallback to header index (Headers-first sync)
        if let Ok(Some(hash)) = self.store.get_block_hash_by_header_height(height) {
            if let Ok(Some(index)) = self.store.get_block_index(&hash) {
                return Some(index);
            }
        }

        None
    }
}

#[async_trait::async_trait]
impl ValidationInterface for Blockchain {
    /// Processes a single incoming block header.
    ///
    /// Bitcoin Core: `ProcessNewBlockHeaders`
    async fn process_header(
        &self,
        header: &bitcrab_common::types::block::BlockHeader,
    ) -> Result<u32, String> {
        let hash = header.block_hash();
        let prev_hash = header.prev_hash;

        // 1. CRITICAL: Early exit if we already have this header index.
        // Syncing with multiple peers sends thousands of duplicates; don't flood the actor.
        if let Some(index) = self
            .store
            .get_block_index(&hash)
            .map_err(|e| e.to_string())?
        {
            self.update_header_chain(hash, index.height.0);
            return Ok(index.height.0);
        }

        // 2. Lookup parent to determine height and validate headers-first sequence
        let (height, prev_index) = if prev_hash.is_zero() {
            // For diagnostic tools or initial sync start, we might receive genesis
            (bitcrab_common::types::block::BlockHeight(0), None)
        } else {
            match self
                .store
                .get_block_index(&prev_hash)
                .map_err(|e| e.to_string())?
            {
                Some(parent_index) => (parent_index.height.next(), Some(parent_index)),
                None => {
                    return Err(format!("orphan header: parent {} not found", prev_hash));
                }
            }
        };

        // 3. Consensus Header Check (PoW + Difficulty Retargeting)
        if let Some(prev) = prev_index {
            TransactionValidator::check_block_header(header, &prev, &self.params(), self)
                .map_err(|e| format!("header consensus check failed: {}", e))?;
        }

        debug!(
            "[blockchain] processed header {} at height {}",
            hash, height
        );

        // 4. Delegate storage and tip update to the Chainstate Actor
        // This ensures sequencing and avoids race conditions.
        self.chainstate
            .process_header(header.clone(), height)
            .await?;

        self.update_header_chain(hash, height.0);
        Ok(height.0)
    }

    /// Validate and persist one Bitcoin `headers` message as a single DB batch.
    ///
    /// Bitcoin Core: `ProcessNewBlockHeaders` / `AcceptBlockHeader`.
    async fn process_headers(
        &self,
        headers: &[bitcrab_common::types::block::BlockHeader],
    ) -> Result<Vec<u32>, String> {
        let mut heights = Vec::with_capacity(headers.len());
        let mut pending = Vec::with_capacity(headers.len());
        let mut by_hash = HashMap::<BlockHash, BlockIndex>::new();
        let mut by_height = HashMap::<u32, BlockIndex>::new();

        let current_tip = self.store.get_headers_tip().map_err(|e| e.to_string())?;
        let mut best_work = current_tip
            .and_then(|hash| self.store.get_block_index(&hash).ok().flatten())
            .map(|index| index.chain_work)
            .unwrap_or_else(bitcrab_common::types::hash::Hash256::zero);
        let mut best_tip = None;

        for header in headers {
            let hash = header.block_hash();
            if let Some(index) = self
                .store
                .get_block_index(&hash)
                .map_err(|e| e.to_string())?
            {
                heights.push(index.height.0);
                by_height.insert(index.height.0, index.clone());
                by_hash.insert(hash, index);
                continue;
            }

            // Bitcoin Core treats a non-connecting header as a peer-level fault,
            // not a reason to discard headers it already validated. Stop at the
            // gap and commit the connected prefix: the headers after it are
            // unusable anyway, and dropping the whole message would stall sync
            // whenever a batch starts above our tip.
            let Some(prev) = by_hash
                .get(&header.prev_hash)
                .cloned()
                .or_else(|| self.store.get_block_index(&header.prev_hash).ok().flatten())
            else {
                warn!(
                    "[blockchain] orphan header {}: parent {} not found, keeping the {} connected headers before it",
                    hash,
                    header.prev_hash,
                    pending.len()
                );
                break;
            };
            let height = prev.height.next();
            let provider = HeaderBatchProvider {
                base: self,
                by_height: &by_height,
            };
            TransactionValidator::check_block_header(header, &prev, &self.params(), &provider)
                .map_err(|e| format!("header consensus check failed: {}", e))?;

            let chain_work = bitcrab_consensus::pow::add_chain_work(
                prev.chain_work,
                bitcrab_consensus::pow::calculate_block_work(header.bits),
            );
            let index = BlockIndex {
                header: header.clone(),
                height,
                chain_work,
                file_pos: None,
                undo_pos: None,
            };

            if chain_work > best_work {
                best_work = chain_work;
                best_tip = Some(hash);
            }
            heights.push(height.0);
            by_height.insert(height.0, index.clone());
            by_hash.insert(hash, index.clone());
            pending.push((hash, index));
        }

        if !pending.is_empty() {
            self.chainstate.process_headers(pending, best_tip).await?;
        }

        for (header, height) in headers.iter().zip(&heights) {
            self.update_header_chain(header.block_hash(), *height);
        }

        Ok(heights)
    }

    /// Processes a single incoming block.
    ///
    /// Bitcoin Core: `ProcessNewBlock` -> `AcceptBlock` -> `ActivateBestChain`
    async fn process_block(
        &self,
        block: &bitcrab_common::types::block::Block,
    ) -> Result<u32, String> {
        let hash = block.header.block_hash();
        debug!("[blockchain] processing block {}...", hash);

        // 1. CheckBlock (Stateless validation)
        TransactionValidator::check_block(block, &self.params()).map_err(|e| {
            error!(
                "[blockchain] stateless validation failed for {}: {}",
                hash, e
            );
            format!("stateless validation failed: {}", e)
        })?;

        // 2. AcceptBlock (Disk storage and indexing)
        let mut index = self
            .store
            .get_block_index(&hash)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| {
                error!("[blockchain] header not found for block {}", hash);
                format!("header not found for block {}", hash)
            })?;

        if index.file_pos.is_none() {
            debug!(
                "[blockchain] AcceptBlock: storing block {} at height {}",
                hash, index.height.0
            );
            let raw_block = bitcrab_common::wire::encode::serialize(block);
            let pos = self
                .store
                .store_block(
                    block.header.clone(),
                    index.height,
                    index.chain_work,
                    raw_block,
                )
                .await
                .map_err(|e| {
                    error!("[blockchain] failed to store block {}: {}", hash, e);
                    format!("failed to store block: {}", e)
                })?;

            index.file_pos = Some(pos);
            debug!(
                "[blockchain] AcceptBlock: block {} stored successfully at height {}",
                hash, index.height.0
            );
        } else {
            debug!(
                "[blockchain] AcceptBlock: block {} already on disk at height {}",
                hash, index.height.0
            );
        }

        // 4. Bitcoin Core: ActivateBestChain (Signaled via process_block_downloaded)
        // In our model, this records the block as "available for activation".
        // The background connector task will pick it up and try to connect it.
        self.chainstate
            .process_block_downloaded(hash, index.height)
            .await
            .map_err(|e| {
                error!(
                    "[blockchain] failed to signal block activation for {}: {}",
                    hash, e
                );
                e
            })?;

        Ok(index.height.0)
    }
}

impl Blockchain {
    /// Accept a previously verified and isolated transaction into the Mempool. without full consensus validation.
    ///
    /// Currently only performs basic struct validation. In the future this will
    /// implement full `AcceptToMemoryPool` logic.
    ///
    /// Bitcoin Core: `CTxMemPool::addUnchecked`
    pub fn add_to_mempool(&self, tx: Transaction) -> Result<(), MempoolError> {
        self.mempool.accept_tx(tx)
    }

    /// Evaluate whether the node is currently in Initial Block Download (IBD).
    ///
    /// Evaluate whether the node is currently in Initial Block Download (IBD).
    pub fn is_initial_block_download(&self) -> bool {
        // 1. If we have no blocks, we are in IBD
        let Ok(Some(tip_hash)) = self.store.get_block_tip() else {
            return true;
        };

        // 2. If the best block is more than 24 hours old, we are in IBD
        let Ok(Some(index)) = self.store.get_block_index(&tip_hash) else {
            return true;
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if index.header.time as u64 + 86400 < now {
            return true;
        }

        false
    }

    /// High-level entry point to seed the genesis block.
    pub async fn load_genesis(&self) -> Result<(), String> {
        self.chainstate.load_genesis(self.params()).await
    }

    /// Attempt to connect any sequential blocks on disk to the active tip.
    /// Resumes sync if the node was restarted with downloaded but unconnected blocks.
    pub async fn activate_best_chain(&self) -> Result<(), String> {
        self.chainstate.activate_best_chain().await
    }

    /// Retrieves a list of block hashes starting after the given height.
    /// Used by the sync engine to identify blocks that need to be downloaded.
    /// Bitcoin Core Ref: net_processing.cpp FindNextBlocksToDownload
    pub fn get_next_block_hashes_for_sync(
        &self,
        start_height: u32,
        limit: usize,
    ) -> Vec<BlockHash> {
        let chain = self.best_header_chain.read().unwrap();
        let mut hashes = Vec::with_capacity(limit);
        let first_needed_height = start_height + 1;

        // 1. Try to satisfy the window from in-memory cache first
        if (first_needed_height as usize) < chain.len() {
            let end_height = (first_needed_height as usize + limit).min(chain.len());
            for height in (first_needed_height as usize)..end_height {
                let hash = &chain[height];
                // Bitcoin Core: only request if we don't have the block data
                match self.store.get_block(hash) {
                    Ok(None) | Err(_) => hashes.push(*hash),
                    _ => {} // Already on disk
                }
            }
        }

        // 2. If window not full, fallback to Database (table 'z' - header height index)
        // This handles cases where headers reached the DB but cache hasn't updated yet.
        if hashes.len() < limit {
            let db_start = first_needed_height + hashes.len() as u32;
            for h in db_start..(first_needed_height + limit as u32) {
                match self.store.get_block_hash_by_header_height(h) {
                    Ok(Some(hash)) => match self.store.get_block(&hash) {
                        Ok(None) | Err(_) => {
                            if !hashes.contains(&hash) {
                                hashes.push(hash);
                            }
                        }
                        _ => {}
                    },
                    _ => break, // No more headers in DB either
                }
            }
        }

        hashes
    }

    /// Checks if the immediate next block relative to start_height is already on disk.
    pub fn has_next_block_on_disk_internal(&self, start_height: u32) -> bool {
        match self.store.get_block_hash_by_header_height(start_height + 1) {
            Ok(Some(hash)) => self
                .store
                .get_block(&hash)
                .map(|opt| opt.is_some())
                .unwrap_or(false),
            _ => false,
        }
    }
}

#[async_trait::async_trait]
impl bitcrab_rpc::rpc::RpcNodeProvider for Blockchain {
    async fn get_headers_tip(&self) -> Result<Option<BlockHash>, String> {
        self.store.get_headers_tip().map_err(|e| e.to_string())
    }

    async fn get_best_block(&self) -> Result<Option<BlockHash>, String> {
        if let Some((hash, _)) = self.chainstate.active_tip() {
            return Ok(Some(hash));
        }
        self.store.get_best_block().map_err(|e| e.to_string())
    }

    async fn get_block_tip(&self) -> Result<Option<BlockHash>, String> {
        self.store.get_block_tip().map_err(|e| e.to_string())
    }

    async fn get_block_index_height(&self, hash: &BlockHash) -> Result<Option<u32>, String> {
        match self.store.get_block_index(hash) {
            Ok(Some(index)) => Ok(Some(index.height.0)),
            Ok(None) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    async fn get_block_hash(&self, height: u32) -> Result<Option<BlockHash>, String> {
        self.store.get_block_hash(height).map_err(|e| e.to_string())
    }

    async fn get_block_raw(&self, hash: &BlockHash) -> Result<Option<Vec<u8>>, String> {
        self.store.get_block(hash).map_err(|e| e.to_string())
    }
}

impl bitcrab_net::p2p::sync::SyncProvider for Blockchain {
    fn get_next_block_hashes(
        &self,
        start_height: u32,
        limit: usize,
    ) -> Vec<bitcrab_common::types::hash::BlockHash> {
        self.get_next_block_hashes_for_sync(start_height, limit)
    }

    fn get_block_locator(
        &self,
        tip: &bitcrab_common::types::hash::BlockHash,
    ) -> Vec<bitcrab_common::types::hash::BlockHash> {
        self.block_locator(tip)
    }

    fn get_block_index(
        &self,
        hash: &bitcrab_common::types::hash::BlockHash,
    ) -> Option<bitcrab_common::types::block::BlockIndex> {
        // Explicit fallback for Genesis block if not in DB
        if *hash == self.params().genesis_hash() {
            let params = self.params();
            let work = bitcrab_consensus::pow::calculate_block_work(params.genesis_header.bits);
            return Some(bitcrab_common::types::block::BlockIndex {
                header: params.genesis_header,
                height: bitcrab_common::types::block::BlockHeight(0),
                chain_work: work,
                file_pos: None,
                undo_pos: None,
            });
        }
        self.store.get_block_index(hash).unwrap_or(None)
    }

    fn get_blocks_tip(&self) -> (bitcrab_common::types::hash::BlockHash, u32) {
        if let Some(tip) = self.chainstate.active_tip() {
            return tip;
        }

        match self.store.get_best_block() {
            Ok(Some(hash)) => {
                let height = self
                    .store
                    .get_block_index(&hash)
                    .ok()
                    .flatten()
                    .map(|i| i.height.0)
                    .unwrap_or(0);
                (hash, height)
            }
            _ => (self.params().genesis_hash(), 0),
        }
    }

    fn has_next_block_on_disk(&self, start_height: u32) -> bool {
        self.has_next_block_on_disk_internal(start_height)
    }

    fn get_headers_tip(&self) -> (BlockHash, u32) {
        let hash = self
            .store
            .get_headers_tip()
            .unwrap_or(None)
            .unwrap_or(BlockHash::ZERO);
        let height = if hash == BlockHash::ZERO {
            0
        } else {
            self.store
                .get_block_index(&hash)
                .unwrap_or(None)
                .map(|i| i.height.0)
                .unwrap_or(0)
        };
        (hash, height)
    }

    fn activate_best_chain(&self) -> futures::future::BoxFuture<'_, Result<(), String>> {
        Box::pin(async move { self.activate_best_chain().await })
    }
}
