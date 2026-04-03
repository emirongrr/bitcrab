use bitcrab_net::p2p::connection;
use bitcrab_net::p2p::message::Magic;
use bitcrab_storage::InMemoryBackend;
use bitcrab_net::p2p::sync::SyncManager;
use bitcrab_net::p2p::peer_manager::PeerManager;
use std::sync::Arc;
use tokio::net::TcpListener;
use std::time::Duration;

#[tokio::test]
async fn test_mock_node_strict_drop() {
    let magic = Magic::Mainnet;
    
    // 1. Start a fake remote peer (Mock Node)
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            use tokio::io::AsyncWriteExt;
            
            // The Mock Node acts maliciously: sends complete garbage, or wrong magic bytes.
            // A genuine Bitcoin node should send 24-byte header.
            // We just blast garbage!
            let garbage = [0xFF; 50];
            let _ = socket.write_all(&garbage).await;
            
            // Wait to see if connection gets dropped
            tokio::time::sleep(Duration::from_millis(100)).await;
            
            // Trying to write again should fail because bitcrab strict dropped!
            let res = socket.write_all(&[0x00]).await;
            assert!(res.is_err() || socket.write_all(&[0x00]).await.is_err(), "Bitcrab node did not strict drop connection on garbage stream!");
        }
    });

    // 2. Start Bitcrab manager and connect to the mock
    let storage = Arc::new(InMemoryBackend::open().unwrap());
    let peer_manager = Arc::new(PeerManager::new(magic));
    
    let res = peer_manager.connect_addr(local_addr).await;
    // The connection handshake waits for a valid version message.
    // The mock peer sends 0xFF garbage.
    // The strict drop should cause a protocol error (or reader drop).
    assert!(res.is_err(), "Expected connection/handshake to fail cleanly due to strict drop");

    let _ = server_task.await;
}
