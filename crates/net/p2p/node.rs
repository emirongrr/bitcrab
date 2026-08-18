//! Transport node representing a single Bitcoin P2P loop.
//!
//! Represents one fully handshaked TCP connection to a remote node.
//! Handles message framing, send/recv, and connection state.
//!
//! Bitcoin Core: CNode in src/net.h

use bytes::{Buf, BytesMut};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};
use tracing::{debug, info, warn};

use crate::p2p::{
    codec::{decode_header, encode_header, verify_checksum},
    errors::P2pError,
    message::Magic,
    messages::Message,
    net_types::ConnectionType,
    peer_manager::PeerManager,
};
use tokio_util::sync::CancellationToken;

/// The unique identifier for a node at the transport level.
pub type NodeId = SocketAddr;

/// Handle to a Node used to send outgoing messages to it.
#[derive(Clone)]
pub struct NodeHandle {
    pub addr: NodeId,
    pub services: u64,
    pub conn_type: ConnectionType,
    pub tx: mpsc::Sender<Message>,
    pub cancel: CancellationToken,
}

impl NodeHandle {
    pub async fn send(&self, msg: Message) -> Result<(), P2pError> {
        self.tx
            .send(msg)
            .await
            .map_err(|_| P2pError::ConnectionClosed)
    }

    pub async fn disconnect(&self) -> Result<(), P2pError> {
        info!("[{}] Signaling node disconnect", self.addr);
        self.cancel.cancel();
        Ok(())
    }
}

/// Node corresponds to Core's CNode, handling the transport layer reading and writing loops.
pub struct Node {
    pub id: NodeId,
    magic: Magic,
    reader: OwnedReadHalf,
    writer: OwnedWriteHalf,
}

impl Node {
    pub fn new(id: NodeId, magic: Magic, stream: TcpStream) -> Self {
        let (reader, writer) = stream.into_split();
        Self {
            id,
            magic,
            reader,
            writer,
        }
    }

    /// Spawns the read and write loops, returning a handle to send messages.
    pub fn start(
        self,
        services: u64,
        conn_type: ConnectionType,
        peer_manager: Arc<PeerManager>,
    ) -> NodeHandle {
        // Direct channel for sending messages without taking a lock on this active task.
        let (tx, mut rx) = mpsc::channel::<Message>(1024);
        let token = CancellationToken::new();

        let id = self.id;
        let magic = self.magic;
        let mut writer = self.writer;
        let mut reader = self.reader;
        let writer_token = token.clone();

        // Write Loop: Represents ThreadSocketHandler socket writing responsibility
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = writer_token.cancelled() => {
                        break;
                    }
                    msg_opt = rx.recv() => {
                        let Some(msg) = msg_opt else { break };
                        let payload = msg.encode();
                        if msg.command().name() == "getdata" || msg.command().name() == "block" || msg.command().name() == "getheaders" {
                            info!("[{}] Sending OUTGOING message '{}' with payload of {} bytes", id, msg.command().name(), payload.len());
                        } else {
                            debug!("[{}] Sending OUTGOING message '{}' with payload of {} bytes", id, msg.command().name(), payload.len());
                        }
                        let header = encode_header(magic, &msg.command(), &payload);
                        if writer.write_all(&header).await.is_err() {
                            break;
                        }
                        if writer.write_all(&payload).await.is_err() {
                            break;
                        }
                    }
                }
            }
            debug!("[{}] Writer loop exited", id);
        });

        // Read Loop: Represents ThreadSocketHandler socket reading
        let read_id = id;
        let handle = NodeHandle {
            addr: id,
            services,
            conn_type,
            tx,
            cancel: token.clone(),
        };
        let h_clone = handle.clone();
        let read_token = token.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = read_token.cancelled() => {
                    info!("[{}] Read loop aborted by shutdown signal", read_id);
                }
                _ = Self::read_loop(read_id, h_clone, magic, &mut reader, peer_manager.clone()) => {}
            }
            // Ensure any blocks assigned to this peer are returned to the pool
            peer_manager.finalize_node(&read_id).await;
        });

        handle
    }

    async fn read_loop(
        id: NodeId,
        handle: NodeHandle,
        magic: Magic,
        reader: &mut OwnedReadHalf,
        peer_manager: Arc<PeerManager>,
    ) {
        let mut read_buf = BytesMut::with_capacity(1024 * 64);
        let mut temp_buf = [0u8; 8192];

        info!("[{}] Starting read loop", id);

        // Bitcoin Core disconnects peers after 20 minutes of inactivity.
        let inactivity_timeout = Duration::from_secs(1200);

        loop {
            // Frame parsing
            while read_buf.len() >= 24 {
                let hdr_buf: &[u8; 24] = &read_buf[..24].try_into().unwrap();
                let msg_hdr = match decode_header(hdr_buf, magic) {
                    Ok(hdr) => hdr,
                    Err(P2pError::WrongMagic { .. }) => {
                        read_buf.advance(1);
                        continue;
                    }
                    Err(e) => {
                        warn!("[{}] Invalid message header: {}", id, e);
                        break;
                    }
                };

                let total_len = 24 + msg_hdr.length as usize;
                if read_buf.len() >= total_len {
                    let payload = &read_buf[24..total_len];
                    match verify_checksum(&msg_hdr, payload) {
                        Ok(_) => {
                            if msg_hdr.command.name() == "block" {
                                info!("[{}] Received 'block' command frame, decoding payload ({} bytes)...", id, msg_hdr.length);
                            }
                            match Message::decode(&msg_hdr.command, payload) {
                                Ok(msg) => {
                                    peer_manager.process_message(id, handle.clone(), msg).await;
                                }
                                Err(e) => {
                                    warn!(
                                        "[{}] Failed to decode message '{}' ({} bytes): {}",
                                        id,
                                        msg_hdr.command.name(),
                                        msg_hdr.length,
                                        e
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            warn!(
                                "[{}] Checksum mismatch for message '{}' ({} bytes): {:?}",
                                id,
                                msg_hdr.command.name(),
                                msg_hdr.length,
                                e
                            );
                        }
                    }
                    read_buf.advance(total_len);
                } else {
                    break; // Not enough payload data yet
                }
            }

            // Network read with timeout
            let read_result = timeout(inactivity_timeout, reader.read(&mut temp_buf)).await;

            match read_result {
                Ok(Ok(0)) => break, // EOF
                Ok(Ok(n)) => read_buf.extend_from_slice(&temp_buf[..n]),
                Ok(Err(e)) => {
                    warn!("[{}] Network read error: {}", id, e);
                    break;
                }
                Err(_) => {
                    warn!("[{}] Inactivity timeout (20 min). Disconnecting.", id);
                    break;
                }
            }
        }

        info!("[{}] Read loop terminated", id);
    }
}
