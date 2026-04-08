use std::sync::atomic::{AtomicU64, Ordering};

/// Global metrics for the Bitcrab P2P network.
pub struct Metrics {
    pub connected_peers: AtomicU64,
    pub total_blocks_downloaded: AtomicU64,
    pub total_headers_synced: AtomicU64,
    pub handshake_failures: AtomicU64,
    pub inbound_connections: AtomicU64,
    pub outbound_connections: AtomicU64,
}

impl Metrics {
    const fn new() -> Self {
        Self {
            connected_peers: AtomicU64::new(0),
            total_blocks_downloaded: AtomicU64::new(0),
            total_headers_synced: AtomicU64::new(0),
            handshake_failures: AtomicU64::new(0),
            inbound_connections: AtomicU64::new(0),
            outbound_connections: AtomicU64::new(0),
        }
    }

    pub fn inc_connected_peers(&self) {
        self.connected_peers.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_connected_peers(&self) {
        self.connected_peers.fetch_sub(1, Ordering::Relaxed);
    }
}

pub static METRICS: Metrics = Metrics::new();
