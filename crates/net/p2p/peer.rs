//! A single Bitcoin P2P peer connection.
//!
//! Represents one fully handshaked TCP connection to a remote node.
//! Handles message framing, send/recv, and connection state.
//!
//! Bitcoin Core: CNode in src/net.h

use bytes::{Buf, BytesMut};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::oneshot;
use tokio::time::{interval, Duration, Instant};
use tracing::{debug, info, warn};

use super::{
    actor::{ActorError, ActorRef},
    codec::{decode_header, encode_header, verify_checksum},
    errors::P2pError,
    message::Magic,
    messages::{
        ping::{Ping, Pong},
        Message,
    },
    peer_table::PeerTable,
};

/// Messages sent to the PeerActor via PeerHandle.
pub enum PeerMessage {
    /// Send a protocol message to the remote peer.
    Send(Message),
    /// Request peer information (version, services, etc).
    GetInfo(oneshot::Sender<PeerInfo>),
    /// Disconnect this peer.
    Disconnect,
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub version: i32,
    pub user_agent: String,
    pub services: u64,
    pub start_height: i32,
    pub latency: Option<Duration>,
    pub conntime: u64,
}

/// Handle to a PeerActor.
#[derive(Clone)]
pub struct PeerHandle {
    pub addr: SocketAddr,
    pub actor: ActorRef<PeerMessage>,
}

impl PeerHandle {
    pub async fn send(&self, msg: Message) -> Result<(), ActorError> {
        self.actor.cast(PeerMessage::Send(msg)).await
    }

    pub async fn get_info(&self) -> Result<PeerInfo, ActorError> {
        self.actor.call(|tx| PeerMessage::GetInfo(tx)).await
    }

    pub async fn disconnect(&self) -> Result<(), ActorError> {
        self.actor.cast(PeerMessage::Disconnect).await
    }
}

/// The internal actor that manages a single peer connection.
struct PeerActor {
    addr: SocketAddr,
    magic: Magic,
    stream: TcpStream,
    receiver: Option<Receiver<PeerMessage>>,

    inbound_tx: Sender<Message>,
    table: PeerTable,

    // Metadata
    version: i32,
    user_agent: String,
    start_height: i32,
    services: u64,

    // Internal State
    pending_pings: HashMap<u64, Instant>,
    latency: Option<Duration>,
    ban_list: Arc<Mutex<HashMap<std::net::IpAddr, Instant>>>,
    conntime: Instant,
    read_buf: BytesMut,
}

impl PeerActor {
    async fn run(mut self) {
        let mut ping_interval = interval(Duration::from_secs(120));
        let mut receiver = self.receiver.take().expect("receiver already taken");

        loop {
            tokio::select! {
                // 1. Handle messages from the PeerHandle
                Some(msg) = receiver.recv() => {

                    match msg {
                        PeerMessage::Send(p2p_msg) => {
                            if let Err(e) = self.send_to_stream(&p2p_msg).await {
                                warn!("[{}] failed to send message {}: {}", self.addr, p2p_msg, e);
                                break;
                            }
                        }

                        PeerMessage::GetInfo(tx) => {
                            let info = PeerInfo {
                                addr: self.addr,
                                version: self.version,
                                user_agent: self.user_agent.clone(),
                                services: self.services,
                                start_height: self.start_height,
                                latency: self.latency,
                                conntime: self.conntime.elapsed().as_secs(),
                            };
                            let _ = tx.send(info);
                        }
                        PeerMessage::Disconnect => {
                            info!("[{}] disconnect requested", self.addr);
                            break;
                        }
                    }
                }

                // 2. Handle periodic Pings
                _ = ping_interval.tick() => {
                    if let Err(e) = self.send_ping().await {
                        warn!("[{}] failed to send keepalive ping: {}", self.addr, e);
                        break;
                    }
                }

                // 3. Handle incoming data from the socket
                res = self.read_message() => {
                    match res {
                        Ok(Some(msg)) => {
                            if let Err(e) = self.handle_incoming(msg).await {
                                debug!("[{}] error handling incoming message: {}", self.addr, e);
                                // Depending on error, we might want to continue or break.
                                // For protocol errors, we often break/disconnect.
                            }
                        }
                        Ok(None) => {
                            info!("[{}] connection closed by remote", self.addr);
                            break;
                        }
                        Err(e) => {
                            warn!("[{}] read error: {}", self.addr, e);
                            break;
                        }
                    }
                }
            }
        }
        info!("[{}] PeerActor terminated", self.addr);
        // Explicitly notify the PeerTable that we are gone.
        let _ = self
            .table
            .actor()
            .cast(crate::p2p::peer_table::PeerTableMessage::RemovePeer(
                self.addr,
            ))
            .await;
    }

    async fn send_to_stream(&mut self, msg: &Message) -> Result<(), P2pError> {
        let payload = msg.encode();
        let header = encode_header(self.magic, &msg.command(), &payload);
        self.stream.write_all(&header).await?;
        self.stream.write_all(&payload).await?;
        Ok(())
    }

    async fn send_ping(&mut self) -> Result<(), P2pError> {
        // Check timeout for existing pings (>20m)
        if self
            .pending_pings
            .values()
            .any(|v| v.elapsed().as_secs() > 1200)
        {
            return Err(P2pError::ConnectionFailed {
                addr: self.addr.to_string(),
                reason: "ping timeout".into(),
            });
        }

        let nonce = rand::random::<u64>();
        self.pending_pings.insert(nonce, Instant::now());
        self.send_to_stream(&Message::Ping(Ping { nonce })).await
    }

    async fn read_message(&mut self) -> Result<Option<Message>, P2pError> {
        loop {
            // 1. Try to parse from the existing buffer
            if self.read_buf.len() >= 24 {
                let hdr_buf: &[u8; 24] = &self.read_buf[..24].try_into().unwrap();
                let msg_hdr = match decode_header(hdr_buf, self.magic) {
                    Ok(hdr) => hdr,
                    Err(e) => {
                        self.read_buf.advance(1); // corrupted? skip 1 byte and retry (Bitcoin Core behavior)
                        return Err(e.into());
                    }
                };

                let total_len = 24 + msg_hdr.length as usize;
                if self.read_buf.len() >= total_len {
                    // We have the full message!
                    let payload = &self.read_buf[24..total_len];
                    verify_checksum(&msg_hdr, payload)?;
                    let msg = Message::decode(&msg_hdr.command, payload)
                        .map_err(|e| P2pError::DecodeError(e.to_string()))?;

                    self.read_buf.advance(total_len);
                    return Ok(Some(msg));
                }
            }

            // 2. Not enough data, read more from the stream
            let mut temp_buf = [0u8; 4096];
            match self.stream.read(&mut temp_buf).await {
                Ok(0) => return Ok(None),
                Ok(n) => self.read_buf.extend_from_slice(&temp_buf[..n]),
                Err(e) => return Err(e.into()),
            }
        }
    }

    async fn handle_incoming(&mut self, msg: Message) -> Result<(), P2pError> {
        match msg {
            Message::Ping(ping) => {
                self.send_to_stream(&Message::Pong(Pong { nonce: ping.nonce }))
                    .await?;
            }

            Message::Pong(pong) => {
                if let Some(sent_at) = self.pending_pings.remove(&pong.nonce) {
                    self.latency = Some(sent_at.elapsed());
                }
            }
            Message::GetAddr(_) => {
                debug!(
                    "[{}] received getaddr, responding with known peers",
                    self.addr
                );
                match self.table.get_addresses().await {
                    Ok(addresses) => {
                        let _ = self
                            .send_to_stream(&Message::Addr(crate::p2p::messages::addr::Addr {
                                addresses,
                            }))
                            .await;
                    }
                    Err(e) => {
                        warn!(
                            "[{}] failed to fetch addresses from table: {}",
                            self.addr, e
                        );
                    }
                }
            }
            Message::Addr(addr) => {
                debug!(
                    "[{}] received addr with {} peers",
                    self.addr,
                    addr.addresses.len()
                );
                let _ = self.table.add_addresses(addr.addresses, self.addr).await;
            }
            other => {
                if self.inbound_tx.send(other).await.is_err() {
                    return Err(P2pError::ConnectionClosed);
                }
            }
        }
        Ok(())
    }
}

impl PeerHandle {
    /// Construct from an established, handshaked connection.
    pub(crate) fn start(
        addr: SocketAddr,
        magic: Magic,
        stream: TcpStream,
        version: i32,
        user_agent: String,
        start_height: i32,
        services: u64,
        ban_list: Arc<Mutex<HashMap<std::net::IpAddr, Instant>>>,
        table: PeerTable,
    ) -> (Self, Receiver<Message>) {
        let (actor_tx, actor_rx) = channel(1024);
        let (inbound_tx, inbound_rx) = channel(1024);

        let actor = PeerActor {
            addr,
            magic,
            stream,
            receiver: Some(actor_rx),

            inbound_tx,
            table,
            version,
            user_agent,
            start_height,
            services,
            pending_pings: HashMap::new(),
            latency: None,
            conntime: Instant::now(),
            ban_list,
            read_buf: BytesMut::with_capacity(1024 * 64),
        };

        let addr_clone = addr;
        tokio::spawn(async move {
            actor.run().await;
        });

        (
            Self {
                addr: addr_clone,
                actor: ActorRef::new(actor_tx),
            },
            inbound_rx,
        )
    }
}
