pub mod blocks;
pub mod headers;

use crate::p2p::actor::{Actor, ActorRef};
use crate::p2p::peer_table::PeerTable;
use bitcrab_storage::Store;
use std::sync::Arc;

pub use blocks::{BlockDownloadActor, BlockDownloadMessage};
pub use headers::{HeaderSyncActor, HeaderSyncMessage};

/// Top-level synchronization manager (Supervisor).
#[derive(Clone)]
pub struct SyncManager {
    pub headers: ActorRef<HeaderSyncMessage>,
    pub blocks: ActorRef<BlockDownloadMessage>,
}

impl SyncManager {
    pub fn new(
        store: Store,
        peer_table: PeerTable,
        notifier: Option<
            tokio::sync::mpsc::Sender<(
                bitcrab_common::types::hash::BlockHash,
                bitcrab_common::types::block::BlockHeight,
            )>,
        >,
    ) -> Self {
        // 1. Create BlockDownloadActor first so headers can refer to it
        let mut block_actor = BlockDownloadActor::new(store.clone(), peer_table.clone());
        if let Some(tx) = notifier {
            block_actor = block_actor.with_notifier(tx);
        }
        let blocks = block_actor.spawn();

        // 2. Create HeaderSyncActor with a reference to the block actor
        let headers = HeaderSyncActor::new(store, peer_table, blocks.clone()).spawn();

        Self { headers, blocks }
    }

    /// Notify the sync system that a new peer is available and ready for protocol messages.
    pub async fn notify_peer_connected(&self, peer: crate::p2p::peer::PeerHandle) {
        let _ = self.headers.cast(HeaderSyncMessage::PeerConnected(peer.clone())).await;
        // CRITICAL FIX: Also notify block downloader about the new peer
        let _ = self.blocks.cast(BlockDownloadMessage::PeerConnected(peer)).await;
    }
}
