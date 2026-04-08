//! Functional Testing Harness mimicking Bitcoin Core's C++ P2PInterface.
//!
//! This suite launches an isolated node endpoint and connects a dummy "test node"
//! to verify the protocol behaviors like Ping/Pong compliance, handshake flow,
//! and Sybil resistance.

use bitcrab_net::p2p::{
    codec::{decode_header, encode_header},
    message::Magic,
    messages::{
        ping::{Ping, Pong},
        version::Version,
        verack::Verack,
        Message,
        BitcoinMessage,
    },
    peer_manager::PeerManager,
    peer_table::PeerTable,
    addr_man::AddrMan,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tracing::{info, debug};

use tokio::{net::{TcpListener, TcpStream}, io::{AsyncReadExt, AsyncWriteExt}, time::timeout};

/// Mimics the behavior of `test_framework/p2p.py` `P2PConnection`
struct TestNode {
    stream: TcpStream,
    magic: Magic,
}

impl TestNode {
    async fn connect(addr: SocketAddr, magic: Magic) -> Self {
        let stream = TcpStream::connect(addr).await.unwrap();
        Self { stream, magic }
    }

    async fn send_msg<M: BitcoinMessage>(&mut self, msg: &M) {
        let payload = msg.encode();
        let header = encode_header(self.magic, &M::COMMAND, &payload);
        debug!("Client: Sending {} message, header: {:02X?}", M::COMMAND, header);
        self.stream.write_all(&header).await.unwrap();
        self.stream.write_all(&payload).await.unwrap();
    }

    async fn recv_msg(&mut self) -> Message {
        let mut hdr_buf = [0u8; 24];
        self.stream.read_exact(&mut hdr_buf).await.unwrap();
        let msg_hdr = decode_header(&hdr_buf, self.magic).unwrap();

        let mut payload = vec![0u8; msg_hdr.length as usize];
        if msg_hdr.length > 0 {
            self.stream.read_exact(&mut payload).await.unwrap();
        }

        Message::decode(&msg_hdr.command, &payload).unwrap()
    }
}

#[tokio::test]
async fn test_ping_pong_compliance() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("bitcrab_net=debug,functional_p2p=debug")
        .try_init();

    info!("Starting test_ping_pong_compliance");
    let magic = Magic::Regtest;
    let table = PeerTable::new(AddrMan::new());
    let pm = Arc::new(PeerManager::new(magic, table));

    // Setup a dummy server mimicking the actual `accept_loop`
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let pm_clone = Arc::clone(&pm);
    let server_task = tokio::spawn(async move {
        debug!("Server: Waiting for connection on {}", addr);
        let (stream, peer_addr) = listener.accept().await.expect("Test server failed to accept");
        
        info!("Server: Accepted connection from {}", peer_addr);
        // Initiate handshake process on the incoming connection
        let (peer, mut rx) = pm_clone.handshake(stream, peer_addr, true).await
            .expect("Test server handshake failed");

        info!("Server: Handshake complete for {}", peer_addr);
        // Mimic the production event loop
        loop {
            match rx.recv().await {
                Some(Message::Ping(ping)) => {
                    debug!("Server: Received Ping(nonce={:X}), sending Pong", ping.nonce);
                    peer.send(Message::Pong(Pong { nonce: ping.nonce })).await
                        .expect("Test server failed to send Pong");
                }
                None => {
                    info!("Server: rx channel closed, peer likely disconnected");
                    break;
                }
                _ => {}
            }
        }
        info!("Server: Task finishing");
    });

    // Our TestNode represents the Python test framework connecting
    debug!("Client: Connecting to {}", addr);
    let mut test_node = TestNode::connect(addr, magic).await;

    // Handshake
    info!("Client: Starting handshake");
    test_node.send_msg(&Version::our_version()).await;

    let resp1 = test_node.recv_msg().await;
    debug!("Client: Received initial response: {:?}", resp1);
    assert!(matches!(resp1, Message::Version(_)));

    test_node.send_msg(&Verack).await;

    let resp2 = test_node.recv_msg().await;
    debug!("Client: Received verack response: {:?}", resp2);
    assert!(matches!(resp2, Message::Verack(_)));

    info!("Client: Handshake successful");

    // Ensure ping-pong works
    let test_nonce = 0xAA_BB_CC_DD_EE_FF_00_11;
    info!("Client: Sending Ping with nonce={:X}", test_nonce);
    test_node.send_msg(&Ping { nonce: test_nonce }).await;

    // Expect Pong with the same nonce.
    let pong_nonce = timeout(Duration::from_secs(5), async {
        loop {
            match test_node.recv_msg().await {
                Message::Pong(pong) => {
                    info!("Client: Received Pong with nonce={:X}", pong.nonce);
                    return pong.nonce;
                }
                m => debug!("Client: Received other message during ping-pong: {:?}", m),
            }
        }
    }).await.expect("Timeout waiting for Pong");
    assert_eq!(pong_nonce, test_nonce, "Pong nonce must echo Ping nonce");

    // NEW: Verify GetAddr gossip flow
    info!("Client: Sending GetAddr");
    test_node.send_msg(&crate::p2p::messages::addr::GetAddr).await;

    let addr_count = timeout(Duration::from_secs(5), async {
        loop {
            match test_node.recv_msg().await {
                Message::Addr(addr) => {
                    info!("Client: Received Addr message with {} peers", addr.addresses.len());
                    return addr.addresses.len();
                }
                m => debug!("Client: Received other message during gossip test: {:?}", m),
            }
        }
    }).await.expect("Timeout waiting for Addr response");
    
    // In this test, AddrMan is empty, so we expect 0, but receiving the message 
    // proves the GetAddr -> PeerTable -> Addr loop is working.
    info!("Client: Addr message received successfully (count: {})", addr_count);


    info!("Client: Dropping connection to trigger graceful server shutdown");
    drop(test_node);
    
    // CRITICAL: Ensure the background task didn't crash or panic
    server_task.await.expect("Background server task panicked or failed");
    info!("--- test_ping_pong_compliance finished successfully ---");
}
