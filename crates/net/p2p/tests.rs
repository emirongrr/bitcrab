#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use crate::p2p::addr_man::AddrMan;
    use crate::p2p::{
        connman::Connman,
        net_types::ConnectionType,
        peer_manager::{PeerManager, ValidationInterface},
        peer_table::PeerTable,
        sync::SyncManager,
    };
    use bitcrab_common::types::magic::Magic;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use tokio::time::Duration;

    struct DummyValidation;
    #[async_trait::async_trait]
    impl ValidationInterface for DummyValidation {
        async fn process_header(
            &self,
            _h: &bitcrab_common::types::block::BlockHeader,
        ) -> Result<u32, String> {
            Ok(0)
        }
        async fn process_block(
            &self,
            _b: &bitcrab_common::types::block::Block,
        ) -> Result<u32, String> {
            Ok(0)
        }
    }

    async fn create_test_peer_manager() -> (Arc<Connman>, Arc<PeerManager>, PeerTable) {
        let peer_table = PeerTable::new(AddrMan::new());
        let val = Arc::new(DummyValidation);
        let sync = Arc::new(SyncManager::new());
        let pm = Arc::new(PeerManager::new(peer_table.clone(), val, sync));

        let connman = Arc::new(Connman::new(
            Magic([0, 0, 0, 0]),
            peer_table.clone(),
            pm.clone(),
        ));
        (connman, pm, peer_table)
    }

    #[tokio::test]
    async fn test_peer_discouragement() {
        let (_, pm, pt) = create_test_peer_manager().await;
        let peer_id: SocketAddr = "127.0.0.1:8333".parse().unwrap();

        pm.initialize_node(peer_id, 0, ConnectionType::OutboundFullRelay)
            .await;
        pm.misbehaving(&peer_id, 20, "invalid header").await;
        pm.misbehaving(&peer_id, 80, "another bad header").await;

        assert_eq!(pt.get_peer_count().await, 0);
    }

    #[tokio::test]
    async fn test_dos_bantime() {
        let (connman, _, _) = create_test_peer_manager().await;
        let banned_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let duration = Duration::from_secs(1);

        assert!(!connman.is_banned(&banned_ip));
        connman.ban(banned_ip, duration);
        assert!(connman.is_banned(&banned_ip));

        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(!connman.is_banned(&banned_ip));
    }

    #[tokio::test]
    async fn test_connection_types_frelay() {
        use crate::p2p::messages::version::Version;
        let full = ConnectionType::OutboundFullRelay;
        let block_only = ConnectionType::BlockRelayOnly;
        let feeler = ConnectionType::Feeler;

        assert!(full.is_tx_relay_connection());
        assert!(!block_only.is_tx_relay_connection());
        assert!(!feeler.is_tx_relay_connection());

        let v_full = Version::our_version_with_nonce(1, 0, full.is_tx_relay_connection());
        assert!(v_full.relay);
        let v_block = Version::our_version_with_nonce(1, 0, block_only.is_tx_relay_connection());
        assert!(!v_block.relay);
    }

    #[test]
    fn bitcoin_core_default_connection_quotas() {
        use crate::p2p::net_types::{
            DEFAULT_MAX_PEER_CONNECTIONS, MAX_BLOCK_RELAY_ONLY_CONNECTIONS, MAX_FEELER_CONNECTIONS,
            MAX_INBOUND_CONNECTIONS, MAX_OUTBOUND_FULL_RELAY_CONNECTIONS,
        };

        assert_eq!(DEFAULT_MAX_PEER_CONNECTIONS, 125);
        assert_eq!(MAX_OUTBOUND_FULL_RELAY_CONNECTIONS, 8);
        assert_eq!(MAX_BLOCK_RELAY_ONLY_CONNECTIONS, 2);
        assert_eq!(MAX_FEELER_CONNECTIONS, 1);
        assert_eq!(MAX_INBOUND_CONNECTIONS, 115);
    }
}
