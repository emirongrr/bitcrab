use crate::p2p::{
    messages::{
        getdata::GetData,
        getheaders::GetHeaders,
        inv::{InvType, InvVector},
        Message,
    },
    peer_table::PeerTable,
    sync::{SyncManager, SyncProvider},
};
use bitcrab_common::types::hash::BlockHash;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, info, warn};

/// BlockDownloader is a background worker that orchestrates
/// parallel block downloading from multiple peers.
pub struct BlockDownloader {
    peer_table: PeerTable,
    sync_manager: Arc<SyncManager>,
    chain: Arc<dyn SyncProvider>,
    last_activation_progress: AtomicU64,
    last_tip_height: AtomicU32,
    last_blacklist_clear_height: AtomicU32,
}

// Bitcoin Core downloads ahead of the active chain so validation and network
// I/O can overlap. Signet's small blocks benefit from a larger IBD window.
const BLOCK_DOWNLOAD_WINDOW: u32 = 8192;
// Bitcoin Core uses 16. Signet's much smaller blocks become latency-bound at
// that depth, so Bitcrab uses a bounded 64-entry IBD pipeline after decoupling
// socket reads from block acceptance. Consensus behavior is unchanged.
const MAX_BLOCKS_IN_TRANSIT_PER_PEER: usize = 64;
// Signet blocks are small enough that a request which has not delivered in
// this interval should be reassigned instead of holding the download window.
const BLOCK_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
// Bitcoin Core effectively has a selected headers sync peer; this keeps the
// same locator from being requested repeatedly while a response is outstanding.
const HEADER_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

impl BlockDownloader {
    pub fn new(
        peer_table: PeerTable,
        sync_manager: Arc<SyncManager>,
        chain: Arc<dyn SyncProvider>,
    ) -> Self {
        Self {
            peer_table,
            sync_manager,
            chain,
            last_activation_progress: AtomicU64::new(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            ),
            last_tip_height: AtomicU32::new(0),
            last_blacklist_clear_height: AtomicU32::new(0),
        }
    }

    pub async fn start(self) {
        info!("[block_downloader] starting background worker");
        let mut download_ticker = interval(Duration::from_millis(250));
        let mut activation_ticker = interval(Duration::from_millis(500));

        let self_arc = Arc::new(self);
        let self_clone = self_arc.clone();

        // Connector task: Connects blocks already on disk.
        //
        // Bitcoin Core: ProcessNewBlock calls ActivateBestChain after AcceptBlock.
        // In our async actor model, this background task is the sole caller of
        // ActivateBestChain, matching Core's pattern where only one thread can
        // run ActivateBestChain at a time (via m_chainstate_mutex).
        tokio::spawn(async move {
            loop {
                activation_ticker.tick().await;
                let (tip_hash, tip_height) = self_clone.chain.get_blocks_tip();
                self_clone
                    .sync_manager
                    .update_blocks_tip(tip_hash, tip_height);

                // Bitcoin Core: ActivateBestChain is called after every block during IBD.
                // Chainstate's is_activating flag prevents re-entrant calls.
                if self_clone.sync_manager.is_ibd()
                    || self_clone.chain.has_next_block_on_disk(tip_height)
                {
                    let _ = self_clone.chain.activate_best_chain().await;
                }
            }
        });

        // Downloader task: Requests missing blocks from network
        loop {
            tokio::select! {
                _ = download_ticker.tick() => {}
                _ = self_arc.sync_manager.wait_for_work() => {}
            }

            self_arc.coordinate_headers().await;
            self_arc.coordinate_downloads().await;
        }
    }

    async fn coordinate_headers(&self) {
        if !self.sync_manager.is_ibd() {
            return;
        }

        // Bitcoin Core selects a sync peer that can advance our best-known
        // chain. Prefer the highest advertised NODE_NETWORK peer instead of
        // whichever peer happens to appear first in the peer table.
        let peers = self.peer_table.get_peers(Some(1)).await;
        let Some(peer) = peers
            .into_iter()
            .filter(|peer| self.sync_manager.can_peer_sync_headers(&peer.addr))
            .max_by_key(|peer| self.sync_manager.get_peer_height(&peer.addr))
        else {
            return;
        };

        let (tip_hash, tip_height) = self.sync_manager.get_headers_tip();

        // Guard: Don't request headers if our tip is already at or beyond the peer's height.
        let peer_height = self.sync_manager.get_peer_height(&peer.addr);
        if peer_height > 0 && tip_height >= peer_height {
            return;
        }

        if !self.sync_manager.try_begin_header_request(
            peer.addr,
            tip_hash,
            tip_height,
            HEADER_REQUEST_TIMEOUT,
        ) {
            return;
        }

        debug!(
            "[block_downloader] proactive header sync: requesting from {} starting at {}",
            peer.addr, tip_hash
        );

        if let Err(e) = peer
            .send(Message::GetHeaders(GetHeaders {
                version: 70015,
                locator: self.chain.get_block_locator(&tip_hash),
                stop_hash: BlockHash::ZERO,
            }))
            .await
        {
            warn!(
                "[block_downloader] failed to send GetHeaders to {}: {:?}",
                peer.addr, e
            );
            self.sync_manager.finish_header_request(peer.addr);
            self.peer_table.remove_peer(peer.addr).await;
            self.sync_manager.on_peer_disconnect(peer.addr);
        }
    }

    async fn coordinate_downloads(&self) {
        // 0. Self-healing: Reconcile workloads and reassign stale blocks.
        self.sync_manager.recalculate_workloads();
        let _ = self.sync_manager.prune_timeouts(BLOCK_REQUEST_TIMEOUT);

        // 1. Aggressive Stalling Check (Signet adjusted: 60s Linchpin rotation)
        if let Some((hash, peer_addr, duration)) = self.sync_manager.get_bottleneck_info() {
            if duration >= 60 {
                warn!("[block_downloader] bottleneck detected: block {} stalled from {} for {}s. BLACKLISTING PEER FOR THIS BLOCK.", hash, peer_addr, duration);

                // Record the failure to avoid recycling this peer for the SAME block
                self.sync_manager.record_block_stumble(hash, peer_addr);

                // MISBEHAVIOR: moderate penalty during IBD
                self.peer_table.record_misbehavior(peer_addr, 5).await;

                // Clearing from in-flight allows it to be re-downloaded from someone else THIS loop
                self.sync_manager.mark_block_received(&hash, peer_addr);
            }
        }

        let (headers_tip_hash, h_height) = self.sync_manager.get_headers_tip();
        let (blocks_tip_hash, b_height) = self.chain.get_blocks_tip();

        // Retry previously stalled peers only after meaningful chain progress.
        let last_clear_height = self.last_blacklist_clear_height.load(Ordering::Relaxed);
        if b_height.saturating_sub(last_clear_height) >= 500 {
            self.sync_manager.clear_blacklist();
            self.last_blacklist_clear_height
                .store(b_height, Ordering::Relaxed);
        }

        if headers_tip_hash == blocks_tip_hash {
            debug!("[block_downloader] nothing to do: headers tip matches blocks tip at height {} ({})", b_height, blocks_tip_hash);
            return;
        }

        if headers_tip_hash == BlockHash::ZERO {
            warn!("[block_downloader] stall detected: headers tip is ZERO in SyncManager, but blocks tip is {} ({})", b_height, blocks_tip_hash);
            return;
        }

        let in_flight_count = self.sync_manager.get_in_flight_count();
        if b_height % 10 == 0 || h_height.saturating_sub(b_height) > 100 {
            info!(
                "[block_downloader] coordinating: headers at {}, blocks at {} ({} missing, {} in-flight)", 
                h_height, b_height, h_height.saturating_sub(b_height), in_flight_count
            );
        }

        // 1. Determine download boundaries (Sliding Window)
        let current_height = b_height;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 3. Stall-Breaker: Detect and break synchronization stalls
        // If we stay at the same height while headers are clearly ahead, clear in-flight and retry.
        let last_height = self.last_tip_height.load(Ordering::Relaxed);
        if current_height > last_height {
            self.last_tip_height
                .store(current_height, Ordering::Relaxed);
            self.last_activation_progress.store(now, Ordering::Relaxed);
        } else if h_height > b_height {
            let last_progress = self.last_activation_progress.load(Ordering::Relaxed);
            if now.saturating_sub(last_progress) > 120 {
                warn!("[block_downloader] synchronization STALL detected at height {}. Clearing in-flight blocks and blacklist to force re-request.", b_height);
                self.sync_manager.clear_in_flight();
                self.sync_manager.clear_blacklist();
                self.last_activation_progress.store(now, Ordering::Relaxed); // Reset timer after clearing
            }
        }

        // 4. Fetch hashes of missing blocks within the window
        let missing = self
            .chain
            .get_next_block_hashes(current_height, BLOCK_DOWNLOAD_WINDOW as usize);
        if missing.is_empty() {
            if h_height > b_height {
                warn!("[block_downloader] window is empty despite header lead (headers: {}, blocks: {}). Store might be missing next header index.", h_height, b_height);
            } else {
                debug!(
                    "[block_downloader] window is empty (headers height {}, blocks height {})",
                    h_height, b_height
                );
            }
            return;
        }

        debug!(
            "[block_downloader] window check: current blocks tip {}, found {} missing blocks in {} window.",
            b_height,
            missing.len(),
            BLOCK_DOWNLOAD_WINDOW
        );

        // 3. Find peers that support full blocks and witness (NODE_NETWORK | NODE_WITNESS = 9)
        let all_peers = self.peer_table.get_peers(None).await;
        let active_peers = self.peer_table.get_peers(Some(9)).await;

        let total = all_peers.len();
        let full_nodes = active_peers.len();
        let in_flight_count = self.sync_manager.get_in_flight_count();

        if total > 0 {
            debug!(
                "[block_downloader] Peer status: {} connected, {} Full Nodes. Window: {} missing, {} in-flight.", 
                total, full_nodes, missing.len(), in_flight_count
            );

            // If we have peers but none are detected as full nodes, log their raw bits
            if full_nodes == 0 {
                for peer in &all_peers {
                    debug!(
                        "[block_downloader] Peer {} offers services: {:#018x} (Binary: {:b})",
                        peer.addr, peer.services, peer.services
                    );
                }
            }
        }

        let mut download_peers = active_peers;
        if download_peers.is_empty() {
            warn!("[block_downloader] NO NODE_WITNESS peers available! Falling back to standard full nodes...");
            download_peers = self.peer_table.get_peers(Some(1)).await;
        }

        if download_peers.is_empty() {
            warn!("[block_downloader] CRITICAL: No eligible download peers found (Witness or Network). Waiting for connections... (All peers: {})", total);
            return;
        }

        use std::collections::HashSet;
        let mut assigned_this_round = HashSet::new();

        for peer in download_peers {
            let current_load = self.sync_manager.get_peer_workload(&peer.addr);
            if current_load >= MAX_BLOCKS_IN_TRANSIT_PER_PEER {
                continue;
            }

            let capacity = MAX_BLOCKS_IN_TRANSIT_PER_PEER - current_load;
            let mut to_request = Vec::new();

            // For each peer, we can consider the entire missing window,
            // picking blocks that aren't already in-flight or assigned to someone else in this round.
            for hash in &missing {
                if to_request.len() >= capacity {
                    break;
                }

                if !self.sync_manager.is_block_in_flight(hash)
                    && !assigned_this_round.contains(hash)
                    && self.sync_manager.can_peer_download_block(hash, &peer.addr)
                {
                    to_request.push(*hash);
                    assigned_this_round.insert(*hash);
                }
            }

            if !to_request.is_empty() {
                debug!(
                    "[block_downloader] REQUESTING {} blocks from {}. first: {} (in-flight: {})",
                    to_request.len(),
                    peer.addr,
                    to_request[0],
                    in_flight_count + to_request.len()
                );

                // Pre-calculate heights using their original index in the 'missing' list
                let inventory: Vec<InvVector> = to_request
                    .iter()
                    .map(|hash| {
                        let offset = missing.iter().position(|r| r == hash).unwrap_or(0);
                        let height = b_height + 1 + offset as u32;

                        self.sync_manager
                            .mark_block_in_flight(*hash, peer.addr, height);

                        InvVector {
                            inv_type: InvType::WitnessBlock,
                            hash: *hash.as_bytes(),
                        }
                    })
                    .collect();

                if let Err(e) = peer.send(Message::GetData(GetData { inventory })).await {
                    warn!(
                        "[block_downloader] failed to send GetData to {}: {:?}",
                        peer.addr, e
                    );
                    // Mark as received/cleared so they can be re-requested
                    for hash in &to_request {
                        self.sync_manager.mark_block_received(hash, peer.addr);
                    }
                    self.peer_table.remove_peer(peer.addr).await;
                    self.sync_manager.on_peer_disconnect(peer.addr);
                }
            }
        }
    }
}
