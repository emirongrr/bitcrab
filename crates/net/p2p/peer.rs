//! A single Bitcoin P2P peer connection.
//!
//! Represents one fully handshaked TCP connection to a remote node.
//! Handles message framing, send/recv, and connection state.
//!
//! Bitcoin Core: CNode in src/net.h

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{channel, Sender, Receiver};
use tokio::time::{Instant, Duration};
use tracing::{debug, warn};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::p2p::{
    codec::{decode_header, encode_header, verify_checksum},
    errors::P2pError,
    message::Magic,
    messages::{BitcoinMessage, Message, ping::{Ping, Pong}},
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

    /// Handshake-calculated latency from Ping messages
    pub latency:      Arc<Mutex<Option<Duration>>>,

    /// Channel to send raw bytes to the writer task.
    outbound_tx: Sender<Vec<u8>>,
}

impl Peer {
    /// Construct from an established, handshaked connection.
    pub(crate) fn start(
        addr: SocketAddr,
        magic: Magic,
        stream: TcpStream,
        version: i32,
        user_agent: String,
        start_height: i32,
        services: u64,
        ban_list: Arc<Mutex<HashMap<std::net::IpAddr, Instant>>>
    ) -> (Self, Receiver<Message>) {
        let (outbound_tx, mut outbound_rx) = channel::<Vec<u8>>(1024);
        let (inbound_tx, inbound_rx) = channel::<Message>(1024);
        
        let pending_pings = Arc::new(Mutex::new(HashMap::<u64, Instant>::new()));
        let latency = Arc::new(Mutex::new(None));

        let peer = Self {
            addr,
            magic,
            state: PeerState::Ready,
            version,
            user_agent,
            start_height,
            services,
            latency: Arc::clone(&latency),
            outbound_tx: outbound_tx.clone(),
        };

        // Split the TCP stream into read and write halves.
        let (mut read_half, mut write_half) = stream.into_split();

        // WRITER TASK
        tokio::spawn(async move {
            while let Some(msg_bytes) = outbound_rx.recv().await {
                if write_half.write_all(&msg_bytes).await.is_err() {
                    break;
                }
            }
        });

        let reader_ping_tracker = Arc::clone(&pending_pings);
        let reader_outbound_tx = outbound_tx.clone(); // for auto-Pong replies
        let p_addr = addr.clone();
        
        // READER TASK
        tokio::spawn(async move {
            let mut misbehavior_score = 0;

            loop {
                let mut hdr_buf = [0u8; 24];
                if read_half.read_exact(&mut hdr_buf).await.is_err() {
                    break;
                }

                let msg_hdr = match decode_header(&hdr_buf, magic) {
                    Ok(hdr) => hdr,
                    Err(_) => {
                        // Misbehavior: wrong magic / garbled header
                        misbehavior_score += 20;
                        if misbehavior_score > 100 {
                            ban_list.lock().unwrap().insert(p_addr.ip(), Instant::now() + Duration::from_secs(86400));
                            warn!("[{}] Banned! (Decode Header Error)", p_addr);
                        }
                        warn!("[{}] Stream corrupted at header decode. Strict dropping connection.", p_addr);
                        break; // Strict drop ensures no stream desync reading
                    }
                };

                let mut payload = vec![0u8; msg_hdr.length as usize];
                if msg_hdr.length > 0 {
                    if read_half.read_exact(&mut payload).await.is_err() {
                        break;
                    }
                }

                if verify_checksum(&msg_hdr, &payload).is_err() {
                    misbehavior_score += 50;
                    if misbehavior_score > 100 {
                        ban_list.lock().unwrap().insert(p_addr.ip(), Instant::now() + Duration::from_secs(86400));
                        warn!("[{}] Banned! (Checksum Mismatch)", p_addr);
                    }
                    warn!("[{}] Stream corrupted due to checksum mismatch. Strict dropping connection.", p_addr);
                    break; // Strict drop
                }

                let msg = match Message::decode(&msg_hdr.command, &payload) {
                    Ok(msg) => msg,
                    Err(_) => {
                        misbehavior_score += 20;
                        if misbehavior_score > 100 {
                            ban_list.lock().unwrap().insert(p_addr.ip(), Instant::now() + Duration::from_secs(86400));
                            warn!("[{}] Banned! (Invalid Payload)", p_addr);
                        }
                        warn!("[{}] Stream corrupted due to invalid parsing. Strict dropping connection.", p_addr);
                        break; // Strict drop
                    }
                };

                // Auto-reply to Ping with Pong — never surface Ping to the app layer.
                // Bitcoin Core: net_processing.cpp ProcessMessage ("ping" → send pong)
                if let Message::Ping(ping) = &msg {
                    let pong = Pong { nonce: ping.nonce };
                    let pong_payload = pong.encode();
                    let header = encode_header(magic, &Pong::COMMAND, &pong_payload);
                    let mut full_msg = header.to_vec();
                    full_msg.extend(pong_payload);
                    let _ = reader_outbound_tx.try_send(full_msg);
                    continue; // Don't surface Ping to the app
                }

                // Calculate Latency RTT on Pong
                if let Message::Pong(pong) = &msg {
                    let mut pmap = reader_ping_tracker.lock().unwrap();
                    if let Some(sent_time) = pmap.remove(&pong.nonce) {
                        let rtt = sent_time.elapsed();
                        debug!("[{}] RTT latency: {:?}", p_addr, rtt);
                        *latency.lock().unwrap() = Some(rtt);
                    }
                    continue;
                }

                if inbound_tx.send(msg).await.is_err() {
                    break; // Channel closed, app dropped peer handle
                }
            }
        });

        // KEEPALIVE PINGER TASK
        let pinger_tx = outbound_tx.clone();
        let ping_tracker = Arc::clone(&pending_pings);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(120));
            loop {
                interval.tick().await;

                // Check timeouts for older pings (20 minutes).
                {
                    let map = ping_tracker.lock().unwrap();
                    if map.values().any(|v| v.elapsed().as_secs() > 1200) {
                        warn!("[{}] ping timeout! Dropping connection.", addr);
                        // In a real actor, we'd signal to close the connection/drop.
                        // For now we break, which stops sending pings. Let's break the writer by dropping tx.
                        break;
                    }
                }

                let nonce = rand::random::<u64>();
                ping_tracker.lock().unwrap().insert(nonce, Instant::now());

                let ping = Ping { nonce };
                let ping_payload = ping.encode();
                let header = encode_header(magic, &Ping::COMMAND, &ping_payload);
                let mut full_msg = header.to_vec();
                full_msg.extend(ping_payload);

                if pinger_tx.send(full_msg).await.is_err() {
                    break;
                }
            }
        });

        (peer, inbound_rx)
    }

    /// Send a message to this peer.
    /// Non-blocking: queues the message on the `mpsc::channel`.
    pub fn send<M: BitcoinMessage>(&self, msg: &M) -> Result<(), P2pError> {
        let payload = msg.encode();
        let header  = encode_header(self.magic, &M::COMMAND, &payload);
        let mut full_msg = header.to_vec();
        full_msg.extend(payload);
        
        self.outbound_tx.try_send(full_msg).map_err(|_| P2pError::ConnectionClosed)?;
        debug!("[{}] queued {}", self.addr, M::COMMAND.name());
        Ok(())
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