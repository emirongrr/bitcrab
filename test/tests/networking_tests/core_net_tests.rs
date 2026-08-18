//! Bitcoin Core Ported Tests (net_tests.cpp & denialofservice_tests.cpp)
//!
//! Applies Lambda Class engineering bounds: behavioral integration tests
//! without excessive TCP/socket pointer mocking.

use bitcrab_common::types::magic::Magic;
use bitcrab_net::p2p::{
    addr_man::AddrMan,
    connman::Connman,
    net_types::{
        ConnectionType, DEFAULT_MAX_PEER_CONNECTIONS, MAX_BLOCK_RELAY_ONLY_CONNECTIONS,
        MAX_FEELER_CONNECTIONS, MAX_INBOUND_CONNECTIONS, MAX_OUTBOUND_FULL_RELAY_CONNECTIONS,
    },
    node::NodeHandle,
    peer_manager::{PeerManager, ValidationInterface},
    peer_table::PeerTable,
    sync::SyncManager,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::time::Duration;
use tokio_util::sync::CancellationToken;

/// Dummy Validation Interface
struct DummyValidation;
#[async_trait::async_trait]
impl ValidationInterface for DummyValidation {
    async fn process_header(
        &self,
        _h: &bitcrab_common::types::block::BlockHeader,
    ) -> Result<u32, String> {
        Ok(0)
    }
    async fn process_block(&self, _b: &bitcrab_common::types::block::Block) -> Result<u32, String> {
        Ok(0)
    }
}

async fn create_test_peer_manager() -> (Arc<Connman>, Arc<PeerManager>) {
    let peer_table = PeerTable::new(AddrMan::new());
    let val = Arc::new(DummyValidation);
    let sync = Arc::new(SyncManager::new());
    let pm = Arc::new(PeerManager::new(peer_table.clone(), val, sync));

    let connman = Arc::new(Connman::new(Magic::MAINNET, peer_table, pm.clone()));
    (connman, pm)
}

#[tokio::test]
async fn test_peer_discouragement() {
    let (_, pm) = create_test_peer_manager().await;

    let peer_id: SocketAddr = "127.0.0.1:8333".parse().unwrap();

    // Initialize node
    pm.initialize_node(peer_id, 0, ConnectionType::OutboundFullRelay)
        .await;

    // Simulate minor misbehavior
    pm.misbehaving(&peer_id, 20, "invalid header").await;

    // Re-lock to verify logic
    // We cannot read `self.peers` directly as it's private, but we can verify the
    // discouraging logic through PeerTable interactions. However, a pure behavioral
    // reflection requires tracking the peer map. We know misbehaving is 100 for discouragement.

    // Let's force it to limit
    pm.misbehaving(&peer_id, 80, "another bad header").await;

    // We expect the node to be marked discouraged and trigger a critical failure.
    // In our implementation, `misbehaving >= 100` triggers `peer_table.record_critical_failure`,
    // which deletes it from AddrMan implicitly down the chain.

    assert!(pm.is_peer_discouraged(&peer_id).await);
}

#[tokio::test]
async fn test_dos_bantime() {
    let (connman, _) = create_test_peer_manager().await;

    let banned_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let duration = Duration::from_secs(1);

    assert!(
        !connman.is_banned(&banned_ip),
        "IP should not be banned initially"
    );

    // Hit it with ban
    connman.ban(banned_ip, duration);
    assert!(
        connman.is_banned(&banned_ip),
        "IP should be banned after call"
    );

    // Wait for expiration
    tokio::time::sleep(Duration::from_millis(1100)).await;

    assert!(
        !connman.is_banned(&banned_ip),
        "IP should automatically be unbanned after duration"
    );
}

#[tokio::test]
async fn test_connection_types_frelay() {
    use bitcrab_net::p2p::messages::version::Version;

    let full = ConnectionType::OutboundFullRelay;
    let block_only = ConnectionType::BlockRelayOnly;
    let feeler = ConnectionType::Feeler;

    assert!(
        full.is_tx_relay_connection(),
        "Full Relay evaluates to true"
    );
    assert!(
        !block_only.is_tx_relay_connection(),
        "Block Relay evaluates to false for fRelay"
    );
    assert!(
        !feeler.is_tx_relay_connection(),
        "Feeler evaluates to false for fRelay"
    );

    let v_full = Version::our_version_with_nonce(1, 0, full.is_tx_relay_connection());
    assert!(v_full.relay, "Version logic passes fRelay correctly");

    let v_block = Version::our_version_with_nonce(1, 0, block_only.is_tx_relay_connection());
    assert!(!v_block.relay, "Block-relay sets fRelay=false strictly");
}

/// Bitcoin Core: src/net.h connection slot constants.
#[test]
fn bitcoin_core_default_connection_slot_partition() {
    assert_eq!(DEFAULT_MAX_PEER_CONNECTIONS, 125);
    assert_eq!(MAX_OUTBOUND_FULL_RELAY_CONNECTIONS, 8);
    assert_eq!(MAX_BLOCK_RELAY_ONLY_CONNECTIONS, 2);
    assert_eq!(MAX_FEELER_CONNECTIONS, 1);
    assert_eq!(MAX_INBOUND_CONNECTIONS, 115);
    assert_eq!(
        MAX_INBOUND_CONNECTIONS
            + MAX_OUTBOUND_FULL_RELAY_CONNECTIONS
            + MAX_BLOCK_RELAY_ONLY_CONNECTIONS,
        DEFAULT_MAX_PEER_CONNECTIONS
    );
}

/// Bitcoin Core: FinalizeNode releases the CNode connection slot.
#[tokio::test]
async fn finalized_node_releases_peer_table_slot() {
    let peer_table = PeerTable::new(AddrMan::new());
    let val = Arc::new(DummyValidation);
    let sync = Arc::new(SyncManager::new());
    let pm = Arc::new(PeerManager::new(peer_table.clone(), val, sync));
    let peer_id: SocketAddr = "127.0.0.1:8333".parse().unwrap();
    let (tx, _rx) = tokio::sync::mpsc::channel(1);

    peer_table
        .add_peer(NodeHandle {
            addr: peer_id,
            services: 0,
            conn_type: ConnectionType::OutboundFullRelay,
            tx,
            cancel: CancellationToken::new(),
        })
        .await;
    pm.initialize_node(peer_id, 0, ConnectionType::OutboundFullRelay)
        .await;

    pm.finalize_node(&peer_id).await;

    assert_eq!(peer_table.get_peer_count().await, 0);
    assert_eq!(
        peer_table
            .get_peer_count_by_type(ConnectionType::OutboundFullRelay)
            .await,
        0
    );
}
