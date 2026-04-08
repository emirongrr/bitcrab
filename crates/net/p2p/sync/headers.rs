//! HeaderSyncActor: Handles sequential block header synchronization.

use tracing::{info, warn, debug};
use tokio::time::{interval, Duration};
use std::sync::atomic::Ordering;

use crate::p2p::{
    actor::{Actor, ActorError, Context},
    messages::{Message, headers::Headers, getheaders::GetHeaders},
    peer::PeerHandle,
    peer_table::PeerTable,
    metrics::METRICS,
};
use bitcrab_storage::Store;
use bitcrab_common::types::{block::{BlockHeight}, hash::BlockHash};

pub enum HeaderSyncMessage {
    /// Check for sync peer and request headers if needed.
    Maintenance,
    /// Process incoming headers response.
    HeadersReceived(PeerHandle, Headers),
}

pub struct HeaderSyncActor {
    store: Store,
    peer_table: PeerTable,
    sync_peer: Option<PeerHandle>,
    /// Optimization: local cache for the current best hash to avoid redundant storage reads.
    last_known_tip: Option<BlockHash>,
}

impl HeaderSyncActor {
    pub fn new(store: Store, peer_table: PeerTable) -> Self {
        Self {
            store,
            peer_table,
            sync_peer: None,
            last_known_tip: None,
        }
    }

    async fn request_headers(&mut self) {
        // If no sync peer, try to find one.
        if self.sync_peer.is_none() {
             if let Ok(Some(peer)) = self.peer_table.get_best_peer().await {
                 info!("[headers] selected {} for header sync", peer.addr);
                 self.sync_peer = Some(peer);
             }
        }

        if let Some(ref peer) = self.sync_peer {
            // Fetch current tip from storage or cache.
            let tip = match self.last_known_tip {
                Some(h) => h,
                None => {
                    let h = self.store.get_best_block().unwrap_or(None).unwrap_or(BlockHash::ZERO);
                    self.last_known_tip = Some(h);
                    h
                }
            };
            
            debug!("[headers] requesting headers from {} starting from tip {}", peer.addr, tip);
            let getheaders = GetHeaders::from_tip(tip);
            
            if let Err(e) = peer.send(Message::GetHeaders(getheaders)).await {
                warn!("[headers] failed to request headers from {}: {}", peer.addr, e);
                self.sync_peer = None;
            }
        }
    }

    async fn handle_headers(&mut self, peer: PeerHandle, headers_msg: Headers) -> Result<(), ActorError> {
        let count = headers_msg.headers.len();
        if count == 0 {
            return Ok(());
        }

        info!("[headers] received {} headers from {}", count, peer.addr);

        // Fetch start height for this batch.
        let mut current_height = match self.store.get_best_block() {
            Ok(Some(hash)) => {
                match self.store.get_block_index(&hash) {
                    Ok(Some(idx)) => idx.height.next(),
                    _ => BlockHeight::GENESIS,
                }
            }
            _ => BlockHeight::GENESIS,
        };

        for (i, header) in headers_msg.headers.iter().enumerate() {
            // 1. Basic Consensus Validation: Proof of Work check.
            if !header.meets_target() {
                warn!("[headers] received header with invalid PoW from {}: {}", peer.addr, header.block_hash());
                // TODO: Penalize peer
                return Ok(());
            }

            // 2. Continuity check (optional but recommended): prev_hash should match our current tip.
            // (Skipping complex chain reorg logic for now, assuming sequential sync).

            // 3. Store header.
            let is_best = i == count - 1;
            if let Err(e) = self.store.store_header(header.clone(), current_height, is_best).await {
                warn!("[headers] failed to store header {}: {}", header.block_hash(), e);
                return Ok(());
            }

            current_height = current_height.next();
        }

        // Update local cache and metrics.
        if let Some(last) = headers_msg.headers.last() {
            self.last_known_tip = Some(last.block_hash());
        }
        METRICS.total_headers_synced.fetch_add(count as u64, Ordering::Relaxed);

        // If we got a full batch, request more immediately to speed up IBD.
        if count >= 2000 {
            self.request_headers().await;
        }

        Ok(())
    }
}

impl Actor for HeaderSyncActor {
    type Message = HeaderSyncMessage;

    fn on_start(&mut self, ctx: &mut Context<Self>) -> impl std::future::Future<Output = Result<(), ActorError>> + Send {
        let handle = ctx.handle();
        async move {
            info!("[headers] starting header sync actor");
            tokio::spawn(async move {
                let mut interval = interval(Duration::from_secs(15));
                loop {
                    interval.tick().await;
                    let _ = handle.cast(HeaderSyncMessage::Maintenance).await;
                }
            });
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
                HeaderSyncMessage::Maintenance => {
                    self.request_headers().await;
                }
                HeaderSyncMessage::HeadersReceived(peer, headers) => {
                    let _ = self.handle_headers(peer, headers).await;
                }
            }
            Ok(())
        }
    }
}
