//! PeerTable: The central registry for all active peer connections and known addresses.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use tokio::time::{Duration, Instant};
use tracing::{info, warn};

use super::net_types::ConnectionType;
use super::{addr_man::AddrMan, messages::addr::NetAddr, node::NodeHandle};
use std::sync::Arc;
use tokio::sync::RwLock;

/// The internal state of the PeerTable.
#[derive(Default)]
struct PeerTableState {
    peers: HashMap<SocketAddr, NodeHandle>,
    ban_list: HashMap<IpAddr, Instant>,
    scores: HashMap<SocketAddr, i32>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionCounts {
    pub inbound: usize,
    pub outbound_full_relay: usize,
    pub block_relay_only: usize,
    pub feeler: usize,
}

impl ConnectionCounts {
    pub fn total(self) -> usize {
        self.inbound + self.outbound_full_relay + self.block_relay_only + self.feeler
    }
}

/// A handle to the PeerTable registry.
#[derive(Clone)]
pub struct PeerTable {
    state: Arc<RwLock<PeerTableState>>,
    addr_man: Arc<tokio::sync::Mutex<AddrMan>>,
}

impl PeerTable {
    pub fn new(addr_man: AddrMan) -> Self {
        Self {
            state: Arc::new(RwLock::new(PeerTableState::default())),
            addr_man: Arc::new(tokio::sync::Mutex::new(addr_man)),
        }
    }

    pub async fn add_peer(&self, handle: NodeHandle) {
        let mut state = self.state.write().await;
        info!("[peer_table] added peer {}", handle.addr);
        state.peers.insert(handle.addr, handle);
    }

    pub async fn remove_peer(&self, addr: SocketAddr) {
        let mut state = self.state.write().await;
        if state.peers.remove(&addr).is_some() {
            info!("[peer_table] removed peer {}", addr);
        }
    }

    pub async fn record_misbehavior(&self, addr: SocketAddr, score: i32) {
        let peer_to_disconnect = {
            let mut state = self.state.write().await;
            let current = state.scores.entry(addr).or_insert(0);
            *current += score;
            if *current >= 100 {
                Some(self.ban_peer_internal(&mut state, addr))
            } else {
                None
            }
        };

        if let Some(peer_to_disconnect) = peer_to_disconnect {
            self.finish_ban(addr, peer_to_disconnect).await;
        }
    }

    pub async fn is_banned(&self, ip: IpAddr) -> bool {
        let state = self.state.read().await;
        if let Some(expiry) = state.ban_list.get(&ip) {
            return *expiry > Instant::now();
        }
        false
    }

    pub async fn get_score(&self, addr: SocketAddr) -> i32 {
        let state = self.state.read().await;
        *state.scores.get(&addr).unwrap_or(&0)
    }

    fn ban_peer_internal(
        &self,
        state: &mut PeerTableState,
        addr: SocketAddr,
    ) -> Option<NodeHandle> {
        warn!("[peer_table] banning IP {} (Socket: {})", addr.ip(), addr);
        state
            .ban_list
            .insert(addr.ip(), Instant::now() + Duration::from_secs(86400));
        state.peers.remove(&addr)
    }

    async fn finish_ban(&self, addr: SocketAddr, peer_to_disconnect: Option<NodeHandle>) {
        if let Some(peer) = peer_to_disconnect {
            let _ = peer.disconnect().await;
        }
        self.addr_man.lock().await.record_failure(addr);
    }

    pub async fn record_success(&self, addr: SocketAddr) {
        info!("[peer_table] record success for {}", addr);
        self.addr_man.lock().await.record_success(addr);
    }

    pub async fn record_critical_failure(&self, addr: SocketAddr) {
        let peer_to_disconnect = {
            let mut state = self.state.write().await;
            self.ban_peer_internal(&mut state, addr)
        };
        self.finish_ban(addr, peer_to_disconnect).await;
    }

    pub async fn get_peer_count(&self) -> usize {
        self.state.read().await.peers.len()
    }

    pub async fn get_peer_count_by_type(&self, conn_type: ConnectionType) -> usize {
        self.state
            .read()
            .await
            .peers
            .values()
            .filter(|peer| peer.conn_type == conn_type)
            .count()
    }

    pub async fn get_outbound_peer_count(&self) -> usize {
        self.state
            .read()
            .await
            .peers
            .values()
            .filter(|peer| peer.conn_type.is_outbound() && !peer.conn_type.is_ephemeral())
            .count()
    }

    pub async fn get_connection_counts(&self) -> ConnectionCounts {
        let state = self.state.read().await;
        let mut counts = ConnectionCounts::default();
        for peer in state.peers.values() {
            match peer.conn_type {
                ConnectionType::Inbound => counts.inbound += 1,
                ConnectionType::OutboundFullRelay => counts.outbound_full_relay += 1,
                ConnectionType::BlockRelayOnly => counts.block_relay_only += 1,
                ConnectionType::Feeler => counts.feeler += 1,
            }
        }
        counts
    }

    pub async fn get_best_peer(&self) -> Option<NodeHandle> {
        let state = self.state.read().await;
        state
            .peers
            .values()
            .find(|p| !state.ban_list.contains_key(&p.addr.ip()))
            .cloned()
    }

    pub async fn get_addresses(&self) -> Vec<NetAddr> {
        self.addr_man.lock().await.get_random_sample(1000)
    }

    pub async fn add_addresses(&self, addresses: Vec<NetAddr>, source: SocketAddr) {
        let mut addr_man = self.addr_man.lock().await;
        for addr in addresses {
            addr_man.add(addr.to_socket_addr(), source);
        }
    }

    pub async fn get_best_address(&self, pending: Vec<SocketAddr>) -> Option<SocketAddr> {
        let active: Vec<SocketAddr> = {
            let state = self.state.read().await;
            state.peers.keys().cloned().collect()
        };
        let mut exclude = Vec::with_capacity((active.len() + pending.len()) * 2);
        for addr in active.into_iter().chain(pending) {
            push_address_variants(&mut exclude, addr);
        }

        let addr_man = self.addr_man.lock().await;
        addr_man
            .select_best_ipv4(&exclude)
            .or_else(|| addr_man.select_best(&exclude))
    }

    pub async fn get_peers(&self, service_filter: Option<u64>) -> Vec<NodeHandle> {
        let state = self.state.read().await;
        state
            .peers
            .values()
            .filter(|p| {
                if let Some(mask) = service_filter {
                    (p.services & mask) == mask
                } else {
                    true
                }
            })
            .cloned()
            .collect()
    }

    pub async fn clear(&self) {
        let peers = {
            let mut state = self.state.write().await;
            state
                .peers
                .drain()
                .map(|(_, peer)| peer)
                .collect::<Vec<_>>()
        };
        for peer in peers {
            let _ = peer.disconnect().await;
        }
    }
}

fn push_address_variants(addresses: &mut Vec<SocketAddr>, addr: SocketAddr) {
    addresses.push(addr);
    match addr {
        SocketAddr::V4(v4) => {
            addresses.push(SocketAddr::new(
                IpAddr::V6(v4.ip().to_ipv6_mapped()),
                v4.port(),
            ));
        }
        SocketAddr::V6(v6) => {
            if let Some(v4) = v6.ip().to_ipv4_mapped() {
                addresses.push(SocketAddr::new(IpAddr::V4(v4), v6.port()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    fn node_handle(addr: &str, conn_type: ConnectionType) -> NodeHandle {
        let (tx, _rx) = mpsc::channel(1);
        NodeHandle {
            addr: addr.parse().unwrap(),
            services: 0,
            conn_type,
            tx,
            cancel: CancellationToken::new(),
        }
    }

    #[test]
    fn address_exclusions_cover_ipv4_mapped_ipv6() {
        let ipv4: SocketAddr = "192.0.2.1:8333".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:192.0.2.1]:8333".parse().unwrap();
        let mut addresses = Vec::new();

        push_address_variants(&mut addresses, ipv4);

        assert!(addresses.contains(&ipv4));
        assert!(addresses.contains(&mapped));
    }

    #[tokio::test]
    async fn connection_counts_match_bitcoin_core_connection_classes() {
        let table = PeerTable::new(AddrMan::new());
        table
            .add_peer(node_handle("127.0.0.1:1001", ConnectionType::Inbound))
            .await;
        table
            .add_peer(node_handle(
                "127.0.0.1:1002",
                ConnectionType::OutboundFullRelay,
            ))
            .await;
        table
            .add_peer(node_handle(
                "127.0.0.1:1003",
                ConnectionType::BlockRelayOnly,
            ))
            .await;
        table
            .add_peer(node_handle("127.0.0.1:1004", ConnectionType::Feeler))
            .await;

        let counts = table.get_connection_counts().await;
        assert_eq!(counts.inbound, 1);
        assert_eq!(counts.outbound_full_relay, 1);
        assert_eq!(counts.block_relay_only, 1);
        assert_eq!(counts.feeler, 1);
        assert_eq!(counts.total(), 4);
        assert_eq!(table.get_outbound_peer_count().await, 2);
    }

    #[tokio::test]
    async fn removing_peer_releases_its_connection_class_slot() {
        let table = PeerTable::new(AddrMan::new());
        let peer = node_handle("127.0.0.1:1001", ConnectionType::BlockRelayOnly);
        let addr = peer.addr;

        table.add_peer(peer).await;
        assert_eq!(
            table
                .get_peer_count_by_type(ConnectionType::BlockRelayOnly)
                .await,
            1
        );

        table.remove_peer(addr).await;
        assert_eq!(
            table
                .get_peer_count_by_type(ConnectionType::BlockRelayOnly)
                .await,
            0
        );
    }

    #[tokio::test]
    async fn inbound_connections_do_not_consume_outbound_quota() {
        let table = PeerTable::new(AddrMan::new());
        for port in 1000..1010 {
            table
                .add_peer(node_handle(
                    &format!("127.0.0.1:{port}"),
                    ConnectionType::Inbound,
                ))
                .await;
        }
        table
            .add_peer(node_handle(
                "127.0.0.1:2000",
                ConnectionType::OutboundFullRelay,
            ))
            .await;

        assert_eq!(table.get_peer_count().await, 11);
        assert_eq!(table.get_outbound_peer_count().await, 1);
    }
}
