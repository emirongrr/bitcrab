//! Bitcoin node — orchestrates net and storage.
//!
//! Connects net (PeerManager) with storage (Store) via a sync pipeline:
//!   connect → getheaders → store headers → repeat
//!
//! Bitcoin Core: ChainstateManager + CConnman interaction in src/net_processing.cpp

use std::net::SocketAddr;
use std::sync::Arc;

use bitcrab_net::p2p::{
    message::Magic,
    messages::{
        Message,
        getheaders::GetHeaders,
    },
    peer_manager::PeerManager,
};
use bitcrab_storage::Store;
use bitcrab_common::types::{
    block::BlockHeight,
    hash::BlockHash,
};

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
pub struct Node {
    pub store:        Store,
    pub peer_manager: Arc<PeerManager>,
}

impl Node {
    /// Create an in-memory node for testing.
    pub fn in_memory(magic: Magic) -> Result<Self, NodeError> {
        let store        = Store::in_memory(magic).map_err(NodeError::Storage)?;
        let peer_manager = Arc::new(PeerManager::new(magic));
        Ok(Self { store, peer_manager })
    }

    /// Connect to a peer, send getheaders from our tip, store received headers.
    ///
    /// Returns the number of headers stored.
    ///
    /// Bitcoin Core: SendMessages() → getheaders in src/net_processing.cpp
    pub async fn sync_headers_from(&mut self, addr: SocketAddr) -> Result<usize, NodeError> {
        // Connect and handshake.
        let (peer, mut rx) = self.peer_manager.connect_addr(addr).await?;

        info!("[sync] connected to {addr}, starting header sync");

        // Build locator from our best block, or genesis if empty.
        let tip = self.store
            .get_best_block()?
            .unwrap_or(BlockHash::zero());

        let getheaders = GetHeaders::from_tip(tip);
        peer.send(&getheaders)?;

        info!("[sync] sent getheaders (tip={})", tip);

        // Wait for the headers response.
        let headers_msg = loop {
            match rx.recv().await {
                Some(Message::Headers(h)) => break h,
                Some(other) => {
                    // Ignore non-headers messages (inv, ping, etc.)
                    info!("[sync] ignoring message during header wait: {other}");
                }
                None => return Err(NodeError::ChannelClosed),
            }
        };

        let count = headers_msg.headers.len();
        info!("[sync] received {count} headers from {addr}");

        if count == 0 {
            return Err(NodeError::NoHeaders);
        }

        // Store each header.
        // We don't know exact heights yet — we derive them from chain position.
        // For now: start from best_height + 1, increment per header.
        let start_height = self.best_height()?.map(|h| h.next()).unwrap_or(BlockHeight::GENESIS);

        for (i, header) in headers_msg.headers.iter().enumerate() {
            let height  = BlockHeight(start_height.0 + i as u32);
            let is_best = i == count - 1;
            self.store.store_header(header, height, is_best)?;
        }

        info!("[sync] stored {count} headers, new tip height={}", start_height.0 + count as u32 - 1);

        Ok(count)
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
}
