use crate::p2p::errors::P2pError;
use crate::p2p::peer_manager::PeerManager;
use bitcrab_storage::{StorageBackend, StoreError};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::time::{Duration, Instant};
use tracing::{info, warn};

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("Store Error: {0}")]
    Store(#[from] StoreError),
    #[error("Peer Manager Error: {0}")]
    PeerManager(#[from] P2pError),
    #[error("Timeout while waiting for block {0}")]
    Timeout(String),
}

impl SyncError {
    pub fn is_recoverable(&self) -> bool {
        match self {
            SyncError::Store(_) => false,
            SyncError::PeerManager(_) => true,
            SyncError::Timeout(_) => true,
        }
    }
}

/// Modus Operandi for P2P Syncing
#[derive(Debug, PartialEq, Clone, Default)]
pub enum SyncMode {
    #[default]
    HeaderSync,
    BlockSync,
}

pub struct SyncManager {
    /// In flight requests: Block hash -> (Peer Socket, Requested At)
    in_flight: Arc<Mutex<HashMap<[u8; 32], (SocketAddr, Instant)>>>,
    storage: Arc<dyn StorageBackend>,
    peer_manager: Arc<PeerManager>,
    pub mode: Arc<Mutex<SyncMode>>,
    pub sync_peer: Arc<Mutex<Option<SocketAddr>>>,
    request_timeout: Duration,
}

impl SyncManager {
    pub fn new(storage: Arc<dyn StorageBackend>, peer_manager: Arc<PeerManager>) -> Self {
        Self {
            in_flight: Arc::new(Mutex::new(HashMap::new())),
            storage,
            peer_manager,
            mode: Arc::new(Mutex::new(SyncMode::default())),
            sync_peer: Arc::new(Mutex::new(None)),
            request_timeout: Duration::from_secs(120),
        }
    }

    /// Triggers a sync cycle in the background
    pub async fn start_sync(&self) {
        let in_flight = Arc::clone(&self.in_flight);
        let peer_manager = Arc::clone(&self.peer_manager);
        let timeout_duration = self.request_timeout;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;

                let mut to_remove = Vec::new();
                {
                    let map = in_flight.lock().unwrap();
                    for (hash, (peer, requested_at)) in map.iter() {
                        if requested_at.elapsed() > timeout_duration {
                            warn!("Timeout waiting for block request from peer {}", peer);
                            to_remove.push((*hash, *peer));
                        }
                    }
                }

                // Penalize peers that timed out
                for (hash, peer) in to_remove {
                    info!("Penalizing peer {} for timeout on block request", peer);
                    
                    // Simple peer misbehavior punishment: Ban for 1 hr
                    peer_manager.ban(peer.ip(), Duration::from_secs(3600));

                    in_flight.lock().unwrap().remove(&hash);
                }
            }
        });
    }

    /// Register that we requested a block from a specific peer
    pub fn register_in_flight(&self, hash: [u8; 32], peer: SocketAddr) {
        self.in_flight.lock().unwrap().insert(hash, (peer, Instant::now()));
    }

    /// Mark a block as received (fulfilled)
    pub fn fulfill_request(&self, hash: &[u8; 32]) {
        self.in_flight.lock().unwrap().remove(hash);
    }
}
