//! Bitcoin node — orchestrates net and storage.
//!
//! Connects net (PeerManager) with storage (Store) via a sync pipeline:
//!   connect → getheaders → store headers → repeat
//!
//! Bitcoin Core: ChainstateManager + CConnman interaction in src/net_processing.cpp

use std::net::SocketAddr;
use std::sync::Arc;

use bitcrab_net::p2p::{
    actor::Actor, addr_man::AddrMan, dispatcher::DispatcherActor, message::Magic,
    peer_manager::PeerManager, peer_table::PeerTable, sync::SyncManager,
};

use bitcrab_common::types::{
    block::{Block, BlockHeight},
    hash::BlockHash,
};
use bitcrab_storage::Store;

use thiserror::Error;
use tracing::info;

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum NodeError {
    #[error("storage error: {0}")]
    Storage(#[from] bitcrab_storage::StoreError),

    #[error("network error: {0}")]
    Net(#[from] bitcrab_net::p2p::errors::P2pError),

    #[error("no headers received from peer")]
    NoHeaders,

    #[error("channel closed")]
    ChannelClosed,
}

// ── Node ──────────────────────────────────────────────────────────────────────

/// The main node — owns storage and the peer manager.
#[derive(Clone)]
pub struct Node {
    pub store: Store,
    pub peer_manager: Arc<PeerManager>,
}

impl Node {
    /// Create an in-memory node for testing.
    pub fn in_memory(magic: Magic) -> Result<Self, NodeError> {
        let store = Store::in_memory(magic).map_err(NodeError::Storage)?;
        let table = PeerTable::new(AddrMan::new());
        let sync = SyncManager::new(store.clone(), table.clone(), None);
        let dispatcher = DispatcherActor::new(table.clone(), sync).spawn();
        let peer_manager = Arc::new(PeerManager::new(magic, table, dispatcher));

        Ok(Self {
            store,
            peer_manager,
        })
    }

    /// Start the Bitcoin-compatible RPC server on a background task.
    pub fn start_rpc(&self, addr: SocketAddr) {
        let ctx = bitcrab_rpc::RpcApiContext {
            store: self.store.clone(),
            peer_manager: Arc::clone(&self.peer_manager),
        };

        tokio::spawn(async move {
            if let Err(e) = bitcrab_rpc::start_api(ctx, addr).await {
                tracing::error!("RPC server failed: {}", e);
            }
        });
    }

    /// Current best block height from storage.
    pub fn best_height(&self) -> Result<Option<BlockHeight>, NodeError> {
        let Some(hash) = self.store.get_best_block()? else {
            return Ok(None);
        };
        let Some(entry) = self.store.get_block_index(&hash)? else {
            return Ok(None);
        };
        Ok(Some(entry.height))
    }

    /// Current best block hash from storage.
    pub fn best_hash(&self) -> Result<Option<BlockHash>, NodeError> {
        Ok(self.store.get_best_block()?)
    }

    /// Process a new block: validate its transactions and update the UTXO set.
    ///
    /// Matches Bitcoin Core's `ProcessNewBlock` / `ConnectBlock` logic.
    pub async fn process_block(&self, block: &Block, height: BlockHeight) -> Result<(), NodeError> {
        info!(
            "[node] processing block {} at height {}",
            block.header.block_hash(),
            height
        );

        // 1. Initialize the UTXO view starting from the persistence layer (Store)
        let base_view = bitcrab_consensus::StoreCoinsView::new(self.store.clone());
        let mut cache_view = bitcrab_consensus::CoinsViewCache::new(base_view);

        // 2. Perform consensus validation and connect the block to the cache
        let (_fees, undo) =
            bitcrab_consensus::TransactionValidator::connect_block(block, height, &mut cache_view)
                .map_err(|e| {
                    tracing::error!(
                        "Consensus validation failed for block {}: {}",
                        block.header.block_hash(),
                        e
                    );
                    NodeError::ChannelClosed // TODO: Better error propagation
                })?;

        // 3. Store the reversal state (Undo data) for reorg support
        self.store
            .store_undo(block.header.block_hash(), undo)
            .await
            .map_err(|_| NodeError::ChannelClosed)?;

        // 4. Persist the updated UTXO set and block tip atomically
        let store_view = bitcrab_consensus::StoreCoinsView::new(self.store.clone());
        store_view
            .flush(&cache_view)
            .await
            .map_err(NodeError::Storage)?;

        info!(
            "[node] successfully connected block {}",
            block.header.block_hash()
        );
        Ok(())
    }
}

// (End of Node implementation)
