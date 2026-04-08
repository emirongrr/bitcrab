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
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::time::{Duration, Instant};
use tracing::{debug, info, warn};

use super::{
    actor::{Actor, ActorError, ActorRef, Context},
    codec::{decode_header, encode_header, verify_checksum},
    dispatcher::DispatchMessage,
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
    /// Message received from the remote peer (sent by the reader task).
    Incoming(Message),
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
    writer: OwnedWriteHalf,
    reader: Option<OwnedReadHalf>,

    dispatcher: ActorRef<DispatchMessage>,
    table: PeerTable,

    // Metadata
    version: i32,
    user_agent: String,
    start_height: i32,
    services: u64,

    // Internal State
    pending_pings: HashMap<u64, Instant>,
    latency: Option<Duration>,
    #[allow(dead_code)]
    ban_list: Arc<Mutex<HashMap<std::net::IpAddr, Instant>>>,
    conntime: Instant,
}

impl Actor for PeerActor {
    type Message = PeerMessage;

    fn on_start(
        &mut self,
        ctx: &mut Context<Self>,
    ) -> impl std::future::Future<Output = Result<(), ActorError>> + Send {
        let handle = ctx.handle();
        let mut reader = self.reader.take().expect("reader already taken");
        let magic = self.magic;
        let addr = self.addr;

        async move {
            info!("[{}] starting peer actor and reader task", addr);

            // Spawn Socket Reader Task
            tokio::spawn(async move {
                let mut read_buf = BytesMut::with_capacity(1024 * 64);
                let mut temp_buf = [0u8; 8192];

                loop {
                    while read_buf.len() >= 24 {
                        let hdr_buf: &[u8; 24] = &read_buf[..24].try_into().unwrap();
                        let msg_hdr = match decode_header(hdr_buf, magic) {
                            Ok(hdr) => hdr,
                            Err(_) => {
                                read_buf.advance(1);
                                continue;
                            }
                        };

                        let total_len = 24 + msg_hdr.length as usize;
                        if read_buf.len() >= total_len {
                            let payload = &read_buf[24..total_len];
                            if verify_checksum(&msg_hdr, payload).is_ok() {
                                if let Ok(msg) = Message::decode(&msg_hdr.command, payload) {
                                    if handle.cast(PeerMessage::Incoming(msg)).await.is_err() {
                                        return;
                                    }
                                }
                            }
                            read_buf.advance(total_len);
                        } else {
                            break;
                        }
                    }

                    match reader.read(&mut temp_buf).await {
                        Ok(0) => break,
                        Ok(n) => read_buf.extend_from_slice(&temp_buf[..n]),
                        Err(_) => break,
                    }
                }
                let _ = handle.cast(PeerMessage::Disconnect).await;
            });

            // Start periodic ping sender (Keepalive)
            let ping_handle = ctx.handle();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(120));
                loop {
                    interval.tick().await;
                    if ping_handle
                        .cast(PeerMessage::Send(Message::Ping(Ping {
                            nonce: rand::random(),
                        })))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });

            Ok(())
        }
    }

    fn handle(
        &mut self,
        msg: Self::Message,
        ctx: &mut Context<Self>,
    ) -> impl std::future::Future<Output = Result<(), ActorError>> + Send {
        async move {
            match msg {
                PeerMessage::Send(p2p_msg) => {
                    if let Message::Ping(ping) = &p2p_msg {
                        self.pending_pings.insert(ping.nonce, Instant::now());
                    }
                    if let Err(e) = self.send_to_stream(&p2p_msg).await {
                        warn!("[{}] failed to send message {}: {}", self.addr, p2p_msg, e);
                        return Err(ActorError::Terminated);
                    }
                }
                PeerMessage::Incoming(msg) => {
                    if let Err(e) = self.handle_incoming(msg, ctx.handle()).await {
                        debug!("[{}] error handling incoming message: {}", self.addr, e);
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
                    return Err(ActorError::Terminated);
                }
            }
            Ok(())
        }
    }

    fn on_stop(
        &mut self,
        _ctx: &mut Context<Self>,
    ) -> impl std::future::Future<Output = ()> + Send {
        async move {
            info!("[{}] PeerActor terminated", self.addr);
            let _ = self
                .table
                .actor()
                .cast(crate::p2p::peer_table::PeerTableMessage::RemovePeer(
                    self.addr,
                ))
                .await;
        }
    }
}

impl PeerActor {
    async fn send_to_stream(&mut self, msg: &Message) -> Result<(), P2pError> {
        let payload = msg.encode();
        let header = encode_header(self.magic, &msg.command(), &payload);
        self.writer.write_all(&header).await?;
        self.writer.write_all(&payload).await?;
        Ok(())
    }

    async fn handle_incoming(
        &mut self,
        msg: Message,
        self_actor: ActorRef<PeerMessage>,
    ) -> Result<(), P2pError> {
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

            // All other protocol messages are forwarded to the dispatcher
            other => {
                let handle = PeerHandle {
                    addr: self.addr,
                    actor: self_actor,
                };
                if let Err(e) = self
                    .dispatcher
                    .cast(DispatchMessage::PeerMessage(handle, other))
                    .await
                {
                    warn!("[{}] failed to dispatch message: {}", self.addr, e);
                    return Err(P2pError::ConnectionClosed);
                }
            }
        }
        Ok(())
    }
}

impl PeerHandle {
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
        dispatcher: ActorRef<DispatchMessage>,
    ) -> Self {
        let (reader, writer) = stream.into_split();

        let actor = PeerActor {
            addr,
            magic,
            writer,
            reader: Some(reader),
            dispatcher,
            table,
            version,
            user_agent,
            start_height,
            services,
            pending_pings: HashMap::new(),
            latency: None,
            conntime: Instant::now(),
            ban_list,
        };

        let actor_handle = actor.spawn();

        Self {
            addr,
            actor: actor_handle,
        }
    }
}
