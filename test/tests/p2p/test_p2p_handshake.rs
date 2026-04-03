use bitcrab_net::p2p::message::Magic;
use bitcrab_net::p2p::messages::{version::Version, verack::Verack, Message};
use bitcrab_storage::InMemoryBackend;
use bitcrab_net::p2p::peer_manager::PeerManager;
use tokio::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use super::mock::MockPeer;

/// Scenario A: Correct handshake completes the Connection.
#[tokio::test]
async fn test_handshake_flow_success() {
    let magic = Magic::Mainnet;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        // 1. the mock peer waits for bitcrab to connect
        let mut mock_peer = MockPeer::bind_and_accept(&listener, magic).await;
        
        // 2. Read Bitcrab's version message!
        let msg = mock_peer.read_msg(Duration::from_millis(500)).await.expect("Failed to read version");
        if let Message::Version(v) = msg {
            assert!(v.version > 0);
        } else {
            panic!("Expected Version!");
        }

        // 3. Send out Version and Verack!
        let v_msg = Version::our_version();
        mock_peer.send_msg(&v_msg).await;
        mock_peer.send_msg(&Verack {}).await;

        // 4. Expect Bitcrab's Verack
        let msg2 = mock_peer.read_msg(Duration::from_millis(500)).await.expect("Failed to read verack");
        if let Message::Verack(_) = msg2 {
            // Success!
        } else {
            panic!("Expected Verack!");
        }
    });

    // Node configuration
    let storage = Arc::new(InMemoryBackend::open().unwrap());
    let peer_manager = Arc::new(PeerManager::new(magic));

    // Outbound Connect and Handshake
    let connect_res = peer_manager.connect_addr(local_addr).await;
    assert!(connect_res.is_ok(), "Handshake should succeed");

    let _ = server_task.await;
}
