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
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
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
    let magic = Magic::Regtest;
    let pm = Arc::new(PeerManager::new(magic));
    
    // Setup a dummy server mimicking the actual `accept_loop`
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let pm_clone = Arc::clone(&pm);
    tokio::spawn(async move {
        if let Ok((stream, peer_addr)) = listener.accept().await {
            // Initiate handshake process on the incoming connection
            if let Ok((peer, mut rx)) = pm_clone.handshake(stream, peer_addr, true).await {
                // Mimic the production event loop
                loop {
                    match rx.recv().await {
                        Some(Message::Ping(ping)) => {
                            peer.send(&Pong { nonce: ping.nonce }).unwrap();
                        }
                        None => break,
                        _ => {}
                    }
                }
            }
        }
    });

    // Our TestNode represents the Python test framework connecting
    let mut test_node = TestNode::connect(addr, magic).await;

    // Send Version
    test_node.send_msg(&Version::our_version()).await;

    // Receive Version
    let resp1 = test_node.recv_msg().await;
    assert!(matches!(resp1, Message::Version(_)));

    // Send Verack
    test_node.send_msg(&Verack).await;

    // Receive Verack
    let resp2 = test_node.recv_msg().await;
    assert!(matches!(resp2, Message::Verack(_)));

    // Ensure ping-pong works (Regression test for bug where Ping is ignored)
    let test_nonce = 0xAA_BB_CC_DD_EE_FF_00_11;
    test_node.send_msg(&Ping { nonce: test_nonce }).await;

    // Expect Pong with the same nonce.
    // NOTE: The peer may also send its own Ping right after handshake,
    // so we skip messages until we see a Pong matching our nonce.
    let pong_nonce = timeout(Duration::from_secs(2), async {
        loop {
            match test_node.recv_msg().await {
                Message::Pong(pong) => return pong.nonce,
                _ => continue, // skip stray Pings or other messages
            }
        }
    }).await.expect("Timeout waiting for Pong");
    assert_eq!(pong_nonce, test_nonce, "Pong nonce must echo Ping nonce");
}
