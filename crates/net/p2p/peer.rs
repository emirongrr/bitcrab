//! A single Bitcoin P2P peer connection.
//!
//! Represents one fully handshaked TCP connection to a remote node.
//! Handles message framing, send/recv, and connection state.
//!
//! Bitcoin Core: CNode in src/net.h

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tracing::{debug};

use crate::p2p::{
    codec::{decode_header, encode_header, verify_checksum},
    errors::P2pError,
    message::Magic,
    messages::{BitcoinMessage, Message, ping::Pong},
};

/// State of a peer connection.
///
/// Bitcoin Core: CNode::fSuccessfullyConnected in src/net.h
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerState {
    /// TCP connected, handshake not yet complete.
    Connecting,
    /// Handshake complete, ready for protocol messages.
    Ready,
    /// Disconnected — connection closed or timed out.
    Disconnected,
}

/// A connected Bitcoin P2P peer.
///
/// Bitcoin Core: CNode in src/net.h
/// One Peer per TCP connection. PeerManager holds a collection of these.
pub struct Peer {
    /// Remote address.
    pub addr:         SocketAddr,
    /// Network magic for this connection.
    pub magic:        Magic,
    /// Current connection state.
    pub state:        PeerState,

    // Fields populated after handshake
    /// Peer's protocol version.
    /// Bitcoin Core: CNode::nVersion
    pub version:      i32,
    /// Peer's user agent string.
    /// Bitcoin Core: CNode::cleanSubVer
    pub user_agent:   String,
    /// Peer's reported chain height at connection time.
    /// Bitcoin Core: CNode::nStartingHeight
    pub start_height: i32,
    /// Peer's reported services bitmask.
    /// Bitcoin Core: CNode::nServices
    pub services:     u64,

    pub(crate) stream: TcpStream,
}

impl Peer {
    /// Construct from an established, handshaked connection.
    pub(crate) fn new(
        addr: SocketAddr,
        magic: Magic,
        stream: TcpStream,
        version: i32,
        user_agent: String,
        start_height: i32,
        services: u64,
    ) -> Self {
        Self {
            addr,
            magic,
            state: PeerState::Ready,
            version,
            user_agent,
            start_height,
            services,
            stream,
        }
    }

    /// Send a message to this peer.
    ///
    /// Bitcoin Core: CNode::PushMessage() in src/net.h
    pub async fn send<M: BitcoinMessage>(&mut self, msg: &M) -> Result<(), P2pError> {
        let payload = msg.encode();
        let header  = encode_header(self.magic, &M::COMMAND, &payload);
        self.stream.write_all(&header).await?;
        self.stream.write_all(&payload).await?;
        debug!("[{}] sent {}", self.addr, M::COMMAND.name());
        Ok(())
    }

    /// Read the next message from this peer.
    ///
    /// Automatically responds to Ping with Pong.
    ///
    /// Bitcoin Core: ProcessMessages() in src/net_processing.cpp
    pub async fn recv(&mut self) -> Result<Message, P2pError> {
        loop {
            let mut hdr_buf = [0u8; 24];
            self.stream.read_exact(&mut hdr_buf).await
                .map_err(|_| P2pError::ConnectionClosed)?;

            let msg_hdr = decode_header(&hdr_buf, self.magic)?;

            let mut payload = vec![0u8; msg_hdr.length as usize];
            if msg_hdr.length > 0 {
                self.stream.read_exact(&mut payload).await
                    .map_err(|_| P2pError::ConnectionClosed)?;
            }

            verify_checksum(&msg_hdr, &payload)?;

            let msg = Message::decode(&msg_hdr.command, &payload)
                .map_err(|e| P2pError::DecodeError(e.to_string()))?;

            // Respond to pings automatically — do not surface to caller.
            //
            // Bitcoin Core: ProcessMessage() "ping" handler in src/net_processing.cpp
            if let Message::Ping(ping) = &msg {
                let pong = Pong { nonce: ping.nonce };
                self.send(&pong).await?;
                debug!("[{}] ping → pong {}", self.addr, pong.nonce);
                continue;
            }

            return Ok(msg);
        }
    }

    /// Read the next message with a timeout.
    pub async fn recv_timeout(&mut self, secs: u64) -> Result<Message, P2pError> {
        timeout(Duration::from_secs(secs), self.recv())
            .await
            .map_err(|_| P2pError::HandshakeTimeout { secs })?
    }

    /// Mark this peer as disconnected.
    pub fn disconnect(&mut self) {
        self.state = PeerState::Disconnected;
    }

    /// True if this peer supports NODE_NETWORK.
    ///
    /// Bitcoin Core: NODE_NETWORK = 1 in src/protocol.h
    pub fn has_network(&self) -> bool {
        self.services & 0x01 != 0
    }

    /// True if this peer supports NODE_WITNESS (SegWit).
    ///
    /// Bitcoin Core: NODE_WITNESS = 8 in src/protocol.h
    pub fn has_witness(&self) -> bool {
        self.services & 0x08 != 0
    }
}

impl std::fmt::Debug for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Peer")
            .field("addr",         &self.addr)
            .field("state",        &self.state)
            .field("version",      &self.version)
            .field("user_agent",   &self.user_agent)
            .field("start_height", &self.start_height)
            .finish()
    }
}