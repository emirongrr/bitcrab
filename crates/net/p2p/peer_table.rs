//! PeerTableActor: The central registry for all active peer connections.
//! Replaces the old PeerManager with an actor-based registry.

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, IpAddr};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, Duration};
use tracing::{info, debug, warn};

use super::{
    peer::PeerHandle,
    addr_man::AddrMan,
    actor::{ActorRef, ActorError},
    messages::addr::NetAddr,
};



/// Messages handled by the PeerTableActor.
pub enum PeerTableMessage {
    /// Register a newly connected peer.
    AddPeer(PeerHandle),
    /// Unregister a peer by address.
    RemovePeer(SocketAddr),
    /// Record a protocol violation or "misbehavior" (Bitcoin Core style).
    RecordMisbehavior(SocketAddr, i32),
    /// Record a successful interaction (e.g. good header sync).
    RecordSuccess(SocketAddr),
    /// Record a critical failure (immediate ban).
    RecordCriticalFailure(SocketAddr),
    /// Select the best peer for a specific operation.
    GetBestPeer(oneshot::Sender<Option<PeerHandle>>),
    /// Get the total count of active peers.
    GetPeerCount(oneshot::Sender<usize>),
    /// Get a random sample of addresses for gossip.
    GetAddresses(oneshot::Sender<Vec<NetAddr>>),
    /// Add multiple addresses to the address manager.
    AddAddresses(Vec<NetAddr>, SocketAddr),
    /// Get all active peer handles.
    GetPeers(oneshot::Sender<Vec<PeerHandle>>),
}




/// The internal state of the PeerTable.
struct PeerTableActor {
    peers: HashMap<SocketAddr, PeerHandle>,
    addr_man: AddrMan,
    ban_list: HashMap<IpAddr, Instant>,
    scores: HashMap<SocketAddr, i32>,
    receiver: mpsc::Receiver<PeerTableMessage>,
}

impl PeerTableActor {
    async fn run(mut self) {
        while let Some(msg) = self.receiver.recv().await {
            match msg {
                PeerTableMessage::AddPeer(handle) => {
                    info!("[table] added peer {}", handle.addr);
                    self.peers.insert(handle.addr, handle);
                }
                PeerTableMessage::RemovePeer(addr) => {
                    if self.peers.remove(&addr).is_some() {
                        info!("[table] removed peer {}", addr);
                    }
                }
                PeerTableMessage::RecordMisbehavior(addr, score) => {
                    let current = self.scores.entry(addr).or_insert(0);
                    *current += score;
                    if *current >= 100 {
                        self.ban_peer(addr).await;
                    }
                }
                PeerTableMessage::RecordSuccess(addr) => {
                    info!("[table] record success for {}", addr);
                    self.addr_man.record_success(addr);
                    // Optionally decrease misbehavior score over time
                }
                PeerTableMessage::RecordCriticalFailure(addr) => {
                    warn!("[table] critical failure from {}", addr);
                    self.ban_peer(addr).await;
                }
                PeerTableMessage::GetBestPeer(tx) => {
                    // Selection logic: prioritize peers with low misbehavior and high success
                    let best = self.peers.values()
                        .find(|p| !self.ban_list.contains_key(&p.addr.ip()))
                        .cloned();
                    let _ = tx.send(best);
                }
                PeerTableMessage::GetPeerCount(tx) => {
                    let _ = tx.send(self.peers.len());
                }
                PeerTableMessage::GetAddresses(tx) => {
                    let sample = self.addr_man.get_random_sample(1000);
                    let _ = tx.send(sample);
                }
                PeerTableMessage::AddAddresses(addresses, source) => {
                    debug!("[table] adding {} addresses from {}", addresses.len(), source);
                    for addr in addresses {
                        self.addr_man.add(addr.to_socket_addr(), source);
                    }
                }
                PeerTableMessage::GetPeers(tx) => {
                    let all_peers = self.peers.values().cloned().collect();
                    let _ = tx.send(all_peers);
                }
            }


        }
    }

    async fn ban_peer(&mut self, addr: SocketAddr) {
        warn!("[table] banning IP {} (Socket: {})", addr.ip(), addr);
        self.ban_list.insert(addr.ip(), Instant::now() + Duration::from_secs(86400));
        if let Some(peer) = self.peers.remove(&addr) {
            let _ = peer.disconnect().await;
        }
        self.addr_man.record_failure(addr);
    }
}


/// A handle to the PeerTableActor.
#[derive(Clone)]
pub struct PeerTable {
    actor: ActorRef<PeerTableMessage>,
}

impl PeerTable {
    pub fn new(addr_man: AddrMan) -> Self {

        let (tx, rx) = mpsc::channel(1024);
        let actor = PeerTableActor {
            peers: HashMap::new(),
            addr_man,
            ban_list: HashMap::new(),
            scores: HashMap::new(),
            receiver: rx,
        };

        tokio::spawn(async move {
            actor.run().await;
        });

        Self { 
            actor: ActorRef::new(tx) 
        }
    }

    pub fn actor(&self) -> &ActorRef<PeerTableMessage> {
        &self.actor
    }

    pub async fn add_peer(&self, handle: PeerHandle) -> Result<(), ActorError> {
        self.actor.cast(PeerTableMessage::AddPeer(handle)).await
    }


    pub async fn get_peer_count(&self) -> Result<usize, ActorError> {
        self.actor.call(|tx| PeerTableMessage::GetPeerCount(tx)).await
    }
    
    pub async fn get_best_peer(&self) -> Result<Option<PeerHandle>, ActorError> {
        self.actor.call(|tx| PeerTableMessage::GetBestPeer(tx)).await
    }

    pub async fn record_misbehavior(&self, addr: SocketAddr, score: i32) -> Result<(), ActorError> {
        self.actor.cast(PeerTableMessage::RecordMisbehavior(addr, score)).await
    }

    pub async fn record_critical_failure(&self, addr: SocketAddr) -> Result<(), ActorError> {
        self.actor.cast(PeerTableMessage::RecordCriticalFailure(addr)).await
    }

    pub async fn get_addresses(&self) -> Result<Vec<NetAddr>, ActorError> {
        self.actor.call(|tx| PeerTableMessage::GetAddresses(tx)).await
    }

    pub async fn add_addresses(&self, addrs: Vec<NetAddr>, source: SocketAddr) -> Result<(), ActorError> {
        self.actor.cast(PeerTableMessage::AddAddresses(addrs, source)).await
    }

    pub async fn get_peers(&self) -> Result<Vec<PeerHandle>, ActorError> {
        self.actor.call(|tx| PeerTableMessage::GetPeers(tx)).await
    }
}



