use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::Duration;
use tokio::time::timeout;
use bitcrab_net::p2p::message::Magic;
use bitcrab_net::p2p::messages::{BitcoinMessage, Message};
use bitcrab_net::p2p::codec::{encode_header, decode_header};

/// A Functional Test Harness modeling a remote Bitcoin Peer.
/// Analogous to Bitcoin Core's Python P2PInterface.
pub struct MockPeer {
    pub stream: TcpStream,
    pub magic: Magic,
}

impl MockPeer {
    /// Bind a fake node to localhost and wait for Bitcrab to connect
    pub async fn bind_and_accept(listener: &TcpListener, magic: Magic) -> Self {
        let (stream, _) = listener.accept().await.expect("MockPeer failed to accept connection");
        Self { stream, magic }
    }

    /// Send a genuine, well-formatted Bitcoin P2P message
    pub async fn send_msg<M: BitcoinMessage>(&mut self, msg: &M) {
        let payload = msg.encode();
        let header = encode_header(self.magic, &M::COMMAND, &payload);
        
        let mut full_msg = header.to_vec();
        full_msg.extend_from_slice(&payload);
        
        self.stream.write_all(&full_msg).await.expect("MockPeer failed to send valid message");
    }

    /// Send maliciously crafted / raw garbage bytes directly to the wire
    pub async fn send_raw(&mut self, garbage: &[u8]) {
        self.stream.write_all(garbage).await.expect("MockPeer failed to send raw bytes");
    }

    /// Read raw bytes from the wire until timeout
    pub async fn read_raw(&mut self, size: usize, wait: Duration) -> Result<Vec<u8>, std::io::Error> {
        let mut buf = vec![0u8; size];
        match timeout(wait, self.stream.read_exact(&mut buf)).await {
            Ok(res) => { res?; Ok(buf) }
            Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "Timeout reading raw bytes"))
        }
    }

    /// Attempt to parse the next message. If stream drops, returns Error.
    pub async fn read_msg(&mut self, wait: Duration) -> Result<Message, Box<dyn std::error::Error>> {
        let mut hdr_bytes = [0u8; 24];
        timeout(wait, self.stream.read_exact(&mut hdr_bytes)).await??;
        
        // Use node's own decoding capabilities
        let hdr = decode_header(&hdr_bytes, self.magic)?;
        
        let mut payload = vec![0u8; hdr.length as usize];
        if hdr.length > 0 {
            timeout(wait, self.stream.read_exact(&mut payload)).await??;
        }

        Ok(Message::decode(&hdr.command, &payload)?)
    }

    /// Verifies the socket gets strictly disconnected (dropped) by Bitcrab
    pub async fn assert_disconnected(&mut self, wait: Duration) -> bool {
        let mut buf = [0u8; 1];
        match timeout(wait, self.stream.read(&mut buf)).await {
            Ok(Ok(0)) => true, // Clean close Connection reset
            Ok(Err(_)) => true, // Connection reset / aborted
            _ => false, // Still alive or timed out reading
        }
    }
}
