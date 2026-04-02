//! Manages multiple Bitcoin P2P peer connections.
//!
//! Responsible for:
//! - Connecting to peers and completing the handshake
//! - Maintaining the active peer list
//! - Disconnecting dead or timed-out peers
//! - Providing access to peers for protocol operations
//!
//! Bitcoin Core: CConnman in src/net.h
//!
//! This is a simplified single-threaded version.
//! Full concurrent peer management comes later.
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tracing::{info, debug};

use crate::p2p::{
    codec::{decode_header, encode_header, verify_checksum},
    errors::P2pError,
    message::Magic,
    messages::{BitcoinMessage, Message, version::Version, verack::Verack},
    peer::{Peer, PeerState},
};

/// Minimum protocol version we accept from peers.
///
/// Bitcoin Core: MIN_PEER_PROTO_VERSION = 31800 in src/net_processing.cpp
const MIN_PEER_VERSION: i32 = 31_800;

/// Connection timeout in seconds.
const CONNECT_TIMEOUT_SECS: u64 = 10;

/// Handshake timeout in seconds.
const HANDSHAKE_TIMEOUT_SECS: u64 = 30;

/// Manages a set of active peer connections.
///
/// Bitcoin Core: CConnman in src/net.h
pub struct PeerManager {
    /// Currently connected peers.
    ///
    /// Bitcoin Core: CConnman::vNodes in src/net.h
    peers:  Vec<Peer>,
    /// Network magic for all connections.
    magic:  Magic,
}

impl PeerManager {
    pub fn new(magic: Magic) -> Self {
        Self { peers: Vec::new(), magic }
    }

    /// Connect to a peer address and complete the Bitcoin handshake.
    ///
    /// On success the peer is added to the active peer list.
    ///
    /// Bitcoin Core: CConnman::OpenNetworkConnection() in src/net.cpp
    pub async fn connect(&mut self, addr: &str) -> Result<(), P2pError> {
        let socket_addr: SocketAddr = addr
            .parse()
            .or_else(|_| {
                // addr may be a hostname — resolve it
                use std::net::ToSocketAddrs;
                addr.to_socket_addrs()
                    .map_err(|e| P2pError::ConnectionFailed {
                        addr: addr.to_string(),
                        reason: e.to_string(),
                    })?
                    .next()
                    .ok_or(P2pError::ConnectionFailed {
                        addr: addr.to_string(),
                        reason: "DNS resolution returned no addresses".to_string(),
                    })
            })?;

        info!("connecting to {}", socket_addr);

        let stream = timeout(
            Duration::from_secs(CONNECT_TIMEOUT_SECS),
            TcpStream::connect(socket_addr),
        )
        .await
        .map_err(|_| P2pError::HandshakeTimeout { secs: CONNECT_TIMEOUT_SECS })?
        .map_err(|e| P2pError::ConnectionFailed {
            addr: addr.to_string(),
            reason: e.to_string(),
        })?;

        info!("TCP connected to {}", socket_addr);

        let peer = self.handshake(stream, socket_addr).await?;
        info!(
            "peer ready: {} v{} '{}' height={}",
            peer.addr, peer.version, peer.user_agent, peer.start_height
        );

        self.peers.push(peer);
        Ok(())
    }

    /// Run the version/verack handshake on an established stream.
    ///
    /// Bitcoin Core: version/verack exchange in src/net_processing.cpp
    /// ProcessMessage() handlers for "version" and "verack".
    async fn handshake(
        &self,
        mut stream: TcpStream,
        addr: SocketAddr,
    ) -> Result<Peer, P2pError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Send our version
        let our_version = Version::our_version();
        let payload = our_version.encode();
        let header  = encode_header(self.magic, &Version::COMMAND, &payload);
        stream.write_all(&header).await?;
        stream.write_all(&payload).await?;
        debug!("[{}] sent version", addr);

        let mut peer_version    = 0i32;
        let mut peer_agent      = String::new();
        let mut peer_height     = 0i32;
        let mut peer_services   = 0u64;
        let mut got_version     = false;
        let mut got_verack      = false;

        let result = timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), async {
            loop {
                let mut hdr_buf = [0u8; 24];
                stream.read_exact(&mut hdr_buf).await
                    .map_err(|_| P2pError::ConnectionClosed)?;

                let msg_hdr = decode_header(&hdr_buf, self.magic)?;
                debug!("[{}] received {:?}", addr, msg_hdr.command);

                let mut payload_buf = vec![0u8; msg_hdr.length as usize];
                if msg_hdr.length > 0 {
                    stream.read_exact(&mut payload_buf).await
                        .map_err(|_| P2pError::ConnectionClosed)?;
                }

                verify_checksum(&msg_hdr, &payload_buf)?;

                match Message::decode(&msg_hdr.command, &payload_buf)
                    .map_err(|e| P2pError::DecodeError(e.to_string()))?
                {
                    Message::Version(v) => {
                        if v.version < MIN_PEER_VERSION {
                            return Err(P2pError::PeerVersionTooOld {
                                version: v.version as u32,
                                minimum: MIN_PEER_VERSION as u32,
                            });
                        }

                        peer_version  = v.version;
                        peer_agent    = v.user_agent;
                        peer_height   = v.start_height;
                        peer_services = v.services;

                        info!(
                            "[{}] peer version={} agent='{}' height={}",
                            addr, peer_version, peer_agent, peer_height
                        );

                        // Send verack in response
                        let verack_payload = Verack.encode();
                        let verack_header  = encode_header(
                            self.magic, &Verack::COMMAND, &verack_payload,
                        );
                        stream.write_all(&verack_header).await?;
                        debug!("[{}] sent verack", addr);

                        got_version = true;
                    }

                    Message::Verack(_) => {
                        got_verack = true;
                    }

                    // Some peers send extra messages during handshake — ignore them.
                    other => {
                        debug!("[{}] ignoring {} during handshake", addr, other);
                    }
                }

                if got_version && got_verack {
                    return Ok(());
                }
            }
        })
        .await
        .map_err(|_| P2pError::HandshakeTimeout { secs: HANDSHAKE_TIMEOUT_SECS })?;

        result?;

        info!("[{}] handshake complete", addr);

        Ok(Peer::new(
            addr,
            self.magic,
            stream,
            peer_version,
            peer_agent,
            peer_height,
            peer_services,
        ))
    }

    /// Number of currently connected peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Iterate over connected peers.
    pub fn peers(&self) -> &[Peer] {
        &self.peers
    }

    /// Get a mutable reference to a peer by index.
    pub fn peer_mut(&mut self, index: usize) -> Option<&mut Peer> {
        self.peers.get_mut(index)
    }

    /// Remove all disconnected peers.
    ///
    /// Bitcoin Core: CConnman::DisconnectNodes() in src/net.cpp
    pub fn prune_disconnected(&mut self) {
        let before = self.peers.len();
        self.peers.retain(|p| p.state != PeerState::Disconnected);
        let removed = before - self.peers.len();
        if removed > 0 {
            debug!("pruned {} disconnected peer(s)", removed);
        }
    }

    /// Disconnect all peers.
    pub fn disconnect_all(&mut self) {
        for peer in &mut self.peers {
            peer.disconnect();
        }
        self.prune_disconnected();
    }
}