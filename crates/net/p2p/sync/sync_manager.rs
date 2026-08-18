use bitcrab_common::types::hash::BlockHash;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;
use tracing::{debug, info, warn};

#[derive(Debug, Default)]
struct SyncDownloadState {
    // Bitcoin Core: mapBlocksInFlight
    // We store the addr, the time requested, and the block height.
    in_flight_blocks: HashMap<BlockHash, (SocketAddr, Instant, u32)>,
    // Bitcoin Core: peer workloads
    peer_workload: HashMap<SocketAddr, usize>,
    // Blacklist: which peers failed for which blocks to avoid recycling bottlenecks.
    failed_block_peers: HashMap<BlockHash, Vec<SocketAddr>>,
}

#[derive(Debug, Clone, Copy)]
struct HeaderRequestState {
    peer_addr: SocketAddr,
    locator_tip: BlockHash,
    locator_height: u32,
    requested_at: Instant,
}

/// SyncManager tracks the current state of synchronization.
/// It doesn't run execution loops; it only provides state to other components
/// like `PeerHandler` or `Blockchain` so they know if IBD is active.
#[derive(Debug)]
pub struct SyncManager {
    is_syncing: AtomicBool,
    headers_tip: Mutex<BlockHash>,
    headers_height: std::sync::atomic::AtomicU32,
    blocks_tip: Mutex<BlockHash>,
    blocks_height: std::sync::atomic::AtomicU32,
    last_header_time: AtomicU64,

    download_state: Mutex<SyncDownloadState>,
    // Per-peer height info (from Version message)
    peer_heights: Mutex<HashMap<SocketAddr, u32>>,
    // Bitcoin Core keeps one peer selected for header sync. Bitcrab tracks
    // the outstanding getheaders request so the downloader does not spam the
    // same locator while waiting for a response.
    header_request: Mutex<Option<HeaderRequestState>>,
    header_sync_cooldowns: Mutex<HashMap<SocketAddr, Instant>>,

    // Bitcoin Core: Adaptive timing
    stalling_timeout_secs: AtomicU64,

    // Reactive trigger for the downloader
    work_available: Notify,
}

impl SyncManager {
    /// Creates a SyncManager with specific tips (usually from persistent storage).
    pub fn with_tips(
        headers_tip: BlockHash,
        headers_height: u32,
        blocks_tip: BlockHash,
        blocks_height: u32,
        last_header_time: u64,
    ) -> Self {
        Self {
            is_syncing: AtomicBool::new(false),
            headers_tip: Mutex::new(headers_tip),
            headers_height: std::sync::atomic::AtomicU32::new(headers_height),
            blocks_tip: Mutex::new(blocks_tip),
            blocks_height: std::sync::atomic::AtomicU32::new(blocks_height),
            last_header_time: AtomicU64::new(last_header_time),
            download_state: Mutex::new(SyncDownloadState::default()),
            peer_heights: Mutex::new(HashMap::new()),
            header_request: Mutex::new(None),
            header_sync_cooldowns: Mutex::new(HashMap::new()),
            stalling_timeout_secs: AtomicU64::new(2), // Bitcoin Core default: 2s
            work_available: Notify::new(),
        }
    }

    pub fn new() -> Self {
        Self::with_tips(BlockHash::ZERO, 0, BlockHash::ZERO, 0, 0)
    }

    pub fn is_syncing(&self) -> bool {
        self.is_syncing.load(Ordering::Acquire)
    }

    /// Returns true if the node is in Initial Block Download mode.
    ///
    /// Bitcoin Core: IsInitialBlockDownload() in src/validation.cpp
    pub fn is_ibd(&self) -> bool {
        if self.is_syncing() {
            return true;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let tip_time = self.last_header_time.load(Ordering::Acquire);

        // If tip is more than 24 hours (86400s) behind, we are in IBD
        if tip_time == 0 || now > tip_time + 86400 {
            return true;
        }

        // If blocks are significantly behind headers, we are still in IBD
        let h_height = self.headers_height.load(Ordering::Acquire);
        let b_height = self.blocks_height.load(Ordering::Acquire);
        if h_height > b_height + 144 {
            // About 1 day of blocks if 10min per block
            return true;
        }

        false
    }

    pub fn set_syncing(&self, syncing: bool) {
        self.is_syncing.store(syncing, Ordering::Release);
        self.notify_work_available();
    }

    pub fn get_headers_tip(&self) -> (BlockHash, u32) {
        (
            *self.headers_tip.lock().unwrap(),
            self.headers_height.load(Ordering::Acquire),
        )
    }

    pub fn update_headers_tip(&self, hash: BlockHash, height: u32, timestamp: u64) {
        let mut tip = self.headers_tip.lock().unwrap();
        let current_height = self.headers_height.load(Ordering::Acquire);

        // Only update if the new height is greater than or equal to current
        if height >= current_height {
            *tip = hash;
            self.headers_height.store(height, Ordering::Release);
            self.last_header_time.store(timestamp, Ordering::Release);
            self.notify_work_available();
        }
    }

    pub fn get_blocks_tip(&self) -> (BlockHash, u32) {
        (
            *self.blocks_tip.lock().unwrap(),
            self.blocks_height.load(Ordering::Acquire),
        )
    }

    pub fn update_blocks_tip(&self, hash: BlockHash, height: u32) {
        let mut tip = self.blocks_tip.lock().unwrap();
        let current_height = self.blocks_height.load(Ordering::Acquire);

        if height >= current_height {
            *tip = hash;
            self.blocks_height.store(height, Ordering::Release);
            self.notify_work_available();
        }
    }

    /// Marks a block as being downloaded from a specific peer.
    pub fn mark_block_in_flight(&self, hash: BlockHash, peer_addr: SocketAddr, height: u32) {
        debug!(
            "[sync_manager] Marking block {} in-flight from {} at height {}",
            hash, peer_addr, height
        );
        let mut state = self.download_state.lock().unwrap();
        state
            .in_flight_blocks
            .insert(hash, (peer_addr, Instant::now(), height));
        *state.peer_workload.entry(peer_addr).or_insert(0) += 1;
    }

    /// Marks a block as received (or failed), clearing the in-flight status.
    pub fn mark_block_received(&self, hash: &BlockHash, peer_addr: SocketAddr) {
        let assigned_peer = {
            let mut state = self.download_state.lock().unwrap();
            let assigned_peer = state
                .in_flight_blocks
                .remove(hash)
                .map(|(assigned_peer, _, _)| assigned_peer);
            if let Some(assigned_peer) = assigned_peer {
                if let Some(count) = state.peer_workload.get_mut(&assigned_peer) {
                    if *count > 0 {
                        *count -= 1;
                    }
                }
            }
            assigned_peer
        };

        if let Some(assigned_peer) = assigned_peer {
            debug!(
                "[sync_manager] Clearing block {} from in-flight (assigned to {}, received from {})",
                hash, assigned_peer, peer_addr
            );
            self.notify_work_available();
        } else {
            // This is suspicious: clearing a block that isn't in flight
            debug!(
                "[sync_manager] Failed to clear block {} from in-flight: not found!",
                hash
            );
        }
    }

    pub fn update_peer_height(&self, addr: SocketAddr, height: u32) {
        self.peer_heights.lock().unwrap().insert(addr, height);
    }

    /// Try to reserve the header-sync slot for one getheaders request.
    ///
    /// Returns false while another non-expired request is outstanding.
    pub fn try_begin_header_request(
        &self,
        peer_addr: SocketAddr,
        locator_tip: BlockHash,
        locator_height: u32,
        timeout: Duration,
    ) -> bool {
        if !self.can_peer_sync_headers(&peer_addr) {
            return false;
        }

        let mut request = self.header_request.lock().unwrap();
        if let Some(existing) = *request {
            if existing.requested_at.elapsed() < timeout {
                return false;
            }
            warn!(
                "[sync_manager] header request to {} from height {} timed out after {}s",
                existing.peer_addr,
                existing.locator_height,
                existing.requested_at.elapsed().as_secs()
            );
            self.header_sync_cooldowns
                .lock()
                .unwrap()
                .insert(existing.peer_addr, Instant::now() + timeout);
            *request = None;
            if existing.peer_addr == peer_addr {
                return false;
            }
        }

        *request = Some(HeaderRequestState {
            peer_addr,
            locator_tip,
            locator_height,
            requested_at: Instant::now(),
        });
        true
    }

    /// Returns true when this peer is not cooling down after a header timeout.
    pub fn can_peer_sync_headers(&self, peer_addr: &SocketAddr) -> bool {
        let now = Instant::now();
        let mut cooldowns = self.header_sync_cooldowns.lock().unwrap();
        cooldowns.retain(|_, until| *until > now);
        !cooldowns.contains_key(peer_addr)
    }

    /// Clear the outstanding header-sync slot when a peer responds or fails.
    pub fn finish_header_request(&self, peer_addr: SocketAddr) {
        let cleared = {
            let mut request = self.header_request.lock().unwrap();
            if request
                .as_ref()
                .is_some_and(|state| state.peer_addr == peer_addr)
            {
                let finished = request.take();
                if let Some(state) = finished {
                    debug!(
                        "[sync_manager] header request to {} from {} at height {} completed",
                        state.peer_addr, state.locator_tip, state.locator_height
                    );
                }
                true
            } else {
                false
            }
        };
        self.header_sync_cooldowns
            .lock()
            .unwrap()
            .remove(&peer_addr);

        if cleared {
            self.notify_work_available();
        }
    }

    pub fn has_header_request_in_flight(&self) -> bool {
        self.header_request.lock().unwrap().is_some()
    }

    pub fn get_peer_height(&self, addr: &SocketAddr) -> u32 {
        *self.peer_heights.lock().unwrap().get(addr).unwrap_or(&0)
    }

    /// Returns true if the block is already requested from someone.
    pub fn is_block_in_flight(&self, hash: &BlockHash) -> bool {
        self.download_state
            .lock()
            .unwrap()
            .in_flight_blocks
            .contains_key(hash)
    }

    /// Returns how many blocks are currently in flight for a peer.
    pub fn get_peer_workload(&self, peer_addr: &SocketAddr) -> usize {
        *self
            .download_state
            .lock()
            .unwrap()
            .peer_workload
            .get(peer_addr)
            .unwrap_or(&0)
    }

    pub fn get_in_flight_count(&self) -> usize {
        self.download_state.lock().unwrap().in_flight_blocks.len()
    }

    /// Records that a peer failed/stalled on a specific block.
    pub fn record_block_stumble(&self, hash: BlockHash, peer_addr: SocketAddr) {
        let mut state = self.download_state.lock().unwrap();
        state
            .failed_block_peers
            .entry(hash)
            .or_default()
            .push(peer_addr);
        debug!(
            "[sync_manager] Block {} added to blacklist for peer {}",
            hash, peer_addr
        );
    }

    /// Returns true if the peer is allowed to download this block (not blacklisted).
    pub fn can_peer_download_block(&self, hash: &BlockHash, peer_addr: &SocketAddr) -> bool {
        let state = self.download_state.lock().unwrap();
        if let Some(blacklisted_peers) = state.failed_block_peers.get(hash) {
            !blacklisted_peers.contains(peer_addr)
        } else {
            true
        }
    }

    pub fn get_stalling_timeout(&self) -> u64 {
        self.stalling_timeout_secs.load(Ordering::Acquire)
    }

    pub fn halve_stalling_timeout(&self) {
        let current = self.stalling_timeout_secs.load(Ordering::Acquire);
        if current > 2 {
            let next = (current / 2).max(2);
            self.stalling_timeout_secs.store(next, Ordering::Release);
            debug!("[sync_manager] stalling timeout reduced to {}s", next);
        }
    }

    /// Finds the oldest in-flight block (the bottleneck) and its details.
    pub fn get_bottleneck_info(&self) -> Option<(BlockHash, SocketAddr, u64)> {
        let state = self.download_state.lock().unwrap();

        let mut bottleneck: Option<(BlockHash, SocketAddr, u32, Instant)> = None;

        for (hash, (addr, start_time, height)) in state.in_flight_blocks.iter() {
            if let Some((_, _, best_height, _)) = bottleneck {
                if *height < best_height {
                    bottleneck = Some((*hash, *addr, *height, *start_time));
                }
            } else {
                bottleneck = Some((*hash, *addr, *height, *start_time));
            }
        }

        bottleneck.map(|(hash, addr, _, start_time)| (hash, addr, start_time.elapsed().as_secs()))
    }

    /// Triggers a notification that work might be available (slots opened or new headers).
    pub fn notify_work_available(&self) {
        self.work_available.notify_waiters();
    }

    /// Returns the notification witness to await.
    pub async fn wait_for_work(&self) {
        self.work_available.notified().await;
    }

    /// Clears all in-flight blocks to force a re-request (Stall-Breaker).
    pub fn clear_in_flight(&self) {
        let mut state = self.download_state.lock().unwrap();
        state.in_flight_blocks.clear();
        state.peer_workload.clear();
        debug!("[sync_manager] all in-flight blocks cleared per request");
    }

    /// Clears any blocks that have been in-flight for too long.
    /// Returns a list of peer addresses that timed out.
    pub fn prune_timeouts(&self, timeout: std::time::Duration) -> Vec<SocketAddr> {
        let mut state = self.download_state.lock().unwrap();
        let mut timed_out_peers = Vec::new();
        let mut timed_out_counts: HashMap<SocketAddr, usize> = HashMap::new();

        let mut timed_out_blocks = Vec::new();
        state
            .in_flight_blocks
            .retain(|hash, (addr, start_time, _)| {
                if start_time.elapsed() >= timeout {
                    timed_out_peers.push(*addr);
                    timed_out_blocks.push((*hash, *addr));
                    *timed_out_counts.entry(*addr).or_insert(0) += 1;
                    false // Remove from map
                } else {
                    true // Keep in map
                }
            });

        for (addr, timed_out_count) in timed_out_counts {
            warn!(
                "[sync_manager] {} blocks timed out from peer {} after {}s",
                timed_out_count,
                addr,
                timeout.as_secs()
            );
            if let Some(count) = state.peer_workload.get_mut(&addr) {
                *count = count.saturating_sub(timed_out_count);
            }
        }

        for (hash, addr) in timed_out_blocks {
            let failed_peers = state.failed_block_peers.entry(hash).or_default();
            if !failed_peers.contains(&addr) {
                failed_peers.push(addr);
            }
        }

        if !timed_out_peers.is_empty() {
            self.notify_work_available();
        }

        timed_out_peers
    }

    /// Resets all workload counters based on the actual in-flight map.
    /// This is a self-healing mechanism to recover from any counter drift.
    pub fn recalculate_workloads(&self) {
        let mut state = self.download_state.lock().unwrap();
        let mut workloads = HashMap::new();

        for (addr, _, _) in state.in_flight_blocks.values() {
            *workloads.entry(*addr).or_insert(0) += 1;
        }
        state.peer_workload = workloads;
        debug!(
            "[sync_manager] Workloads recalculated. Total in-flight: {}",
            state.in_flight_blocks.len()
        );
    }

    /// Handles a peer disconnection by clearing their associated in-flight blocks.
    pub fn on_peer_disconnect(&self, addr: SocketAddr) {
        let mut state = self.download_state.lock().unwrap();

        let initial_count = state.in_flight_blocks.len();
        state
            .in_flight_blocks
            .retain(|_, (peer_addr, _, _)| *peer_addr != addr);
        state.peer_workload.remove(&addr);
        let removed = initial_count - state.in_flight_blocks.len();
        drop(state);

        self.finish_header_request(addr);

        if removed > 0 {
            info!(
                "[sync_manager] Released {} blocks from disconnected peer {}",
                removed, addr
            );
            self.notify_work_available();
        }
    }

    /// Clears the entire block-peer blacklist. Call periodically or when chain tip advances significantly.
    pub fn clear_blacklist(&self) {
        self.download_state
            .lock()
            .unwrap()
            .failed_block_peers
            .clear();
    }
}

impl Default for SyncManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn received_block_releases_the_assigned_peer_workload() {
        let sync = SyncManager::new();
        let hash = BlockHash::from_bytes([7; 32]);
        let assigned_peer: SocketAddr = "127.0.0.1:8333".parse().unwrap();
        let delivering_peer: SocketAddr = "127.0.0.2:8333".parse().unwrap();

        sync.mark_block_in_flight(hash, assigned_peer, 1);
        sync.mark_block_received(&hash, delivering_peer);

        assert_eq!(sync.get_peer_workload(&assigned_peer), 0);
        assert_eq!(sync.get_peer_workload(&delivering_peer), 0);
        assert_eq!(sync.get_in_flight_count(), 0);
    }

    #[test]
    fn timed_out_block_is_reassigned_away_from_stalled_peer() {
        let sync = SyncManager::new();
        let hash = BlockHash::from_bytes([8; 32]);
        let stalled_peer: SocketAddr = "127.0.0.1:8333".parse().unwrap();
        let alternate_peer: SocketAddr = "127.0.0.2:8333".parse().unwrap();

        sync.mark_block_in_flight(hash, stalled_peer, 1);
        sync.prune_timeouts(std::time::Duration::ZERO);

        assert_eq!(sync.get_in_flight_count(), 0);
        assert!(!sync.can_peer_download_block(&hash, &stalled_peer));
        assert!(sync.can_peer_download_block(&hash, &alternate_peer));
    }

    #[test]
    fn header_request_slot_serializes_getheaders_until_response() {
        let sync = SyncManager::new();
        let first_peer: SocketAddr = "127.0.0.1:8333".parse().unwrap();
        let second_peer: SocketAddr = "127.0.0.2:8333".parse().unwrap();
        let locator = BlockHash::from_bytes([9; 32]);

        assert!(sync.try_begin_header_request(
            first_peer,
            locator,
            42,
            std::time::Duration::from_secs(60),
        ));
        assert!(sync.has_header_request_in_flight());
        assert!(!sync.try_begin_header_request(
            second_peer,
            locator,
            42,
            std::time::Duration::from_secs(60),
        ));

        sync.finish_header_request(first_peer);

        assert!(!sync.has_header_request_in_flight());
        assert!(sync.try_begin_header_request(
            second_peer,
            locator,
            42,
            std::time::Duration::from_secs(60),
        ));
    }

    #[test]
    fn expired_header_request_can_be_reassigned() {
        let sync = SyncManager::new();
        let stalled_peer: SocketAddr = "127.0.0.1:8333".parse().unwrap();
        let alternate_peer: SocketAddr = "127.0.0.2:8333".parse().unwrap();
        let locator = BlockHash::from_bytes([10; 32]);

        assert!(sync.try_begin_header_request(
            stalled_peer,
            locator,
            42,
            std::time::Duration::from_secs(60),
        ));
        assert!(sync.try_begin_header_request(
            alternate_peer,
            locator,
            42,
            std::time::Duration::ZERO,
        ));
    }

    #[test]
    fn expired_header_request_does_not_immediately_reselect_same_peer() {
        let sync = SyncManager::new();
        let stalled_peer: SocketAddr = "127.0.0.1:8333".parse().unwrap();
        let locator = BlockHash::from_bytes([11; 32]);

        assert!(sync.try_begin_header_request(
            stalled_peer,
            locator,
            42,
            std::time::Duration::from_secs(60),
        ));
        assert!(!sync.try_begin_header_request(
            stalled_peer,
            locator,
            42,
            std::time::Duration::from_secs(60),
        ));
        assert!(!sync.try_begin_header_request(
            stalled_peer,
            locator,
            42,
            std::time::Duration::ZERO,
        ));
    }
}
