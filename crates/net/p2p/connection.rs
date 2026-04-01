//! TCP connection and Bitcoin P2P handshake.
//!
//! Handshake sequence (Bitcoin Core: src/net_processing.cpp):
//!
//! Initiator              Responder
//!   ── version ────────▶
//!   ◀── version ──────────
//!   ── verack  ────────▶
//!   ◀── verack ───────────
//!   [ready]

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tracing::{debug, info};

use bitcrab_common::types::{block::BlockHeader, hash::BlockHash};

use crate::p2p::{
    codec::{decode_header, encode_header, verify_checksum},
    errors::P2pError,
    message::{Magic},
    messages::{
        BitcoinMessage, Message,
        version::Version,
        verack::Verack,
        ping::Pong,
        getheaders::GetHeaders,
    },
};

/// A connected, handshaked peer.
pub struct Connection {
    pub stream:       TcpStream,
    pub magic:        Magic,
    pub peer_version: i32,
    pub peer_agent:   String,
    pub peer_height:  i32,
}

impl Connection {
    /// Send a message to the peer.
    async fn send<M: BitcoinMessage>(&mut self, msg: &M) -> Result<(), P2pError> {
        let payload = msg.encode();
        let header  = encode_header(self.magic, &M::COMMAND, &payload);
        self.stream.write_all(&header).await?;
        self.stream.write_all(&payload).await?;
        debug!("sent {}", M::COMMAND.name());
        Ok(())
    }

    /// Read the next message from the peer.
    async fn recv(&mut self) -> Result<Message, P2pError> {
        let mut hdr_buf = [0u8; 24];
        self.stream.read_exact(&mut hdr_buf).await?;
        let msg_hdr = decode_header(&hdr_buf, self.magic)?;

        let mut payload = vec![0u8; msg_hdr.length as usize];
        if msg_hdr.length > 0 {
            self.stream.read_exact(&mut payload).await?;
        }
        verify_checksum(&msg_hdr, &payload)?;

        Message::decode(&msg_hdr.command, &payload)
            .map_err(|e| P2pError::DecodeError(e.to_string()))
    }

    /// Send getheaders and wait for headers response.
    ///
    /// Bitcoin Core: SendMessages() → getheaders in src/net_processing.cpp
    pub async fn get_headers(
        &mut self,
        locator: Vec<BlockHash>,
    ) -> Result<Vec<BlockHeader>, P2pError> {
        let msg = GetHeaders::from_tip(locator.into_iter().next().unwrap_or(BlockHash::ZERO));
        self.send(&msg).await?;
        debug!("sent getheaders");

        loop {
            match self.recv().await? {
                Message::Headers(h) => {
                    info!("received {} headers", h.headers.len());
                    return Ok(h.headers);
                }
                Message::Ping(ping) => {
                    // Respond to pings while waiting
                    let pong = Pong { nonce: ping.nonce };
                    self.send(&pong).await?;
                }
                other => debug!("ignoring {} while waiting for headers", other),
            }
        }
    }
}

/// Connect and complete handshake.
pub async fn connect(addr: &str, magic: Magic) -> Result<Connection, P2pError> {
    info!("connecting to {}", addr);

    let stream = timeout(Duration::from_secs(10), TcpStream::connect(addr))
        .await
        .map_err(|_| P2pError::HandshakeTimeout { secs: 10 })?
        .map_err(P2pError::Io)?;

    info!("TCP connected to {}", addr);
    handshake(stream, magic, addr).await
}

async fn handshake(
    mut stream: TcpStream,
    magic: Magic,
    addr: &str,
) -> Result<Connection, P2pError> {
    // Send our version
    let our_version = Version::our_version();
    let payload = our_version.encode();
    let header  = encode_header(magic, &Version::COMMAND, &payload);
    stream.write_all(&header).await?;
    stream.write_all(&payload).await?;
    debug!("sent version");

    let mut peer_version = 0i32;
    let mut peer_agent   = String::new();
    let mut peer_height  = 0i32;
    let mut got_version  = false;
    let mut got_verack   = false;

    timeout(Duration::from_secs(30), async {
        loop {
            let mut hdr_buf = [0u8; 24];
            stream.read_exact(&mut hdr_buf).await?;
            let msg_hdr = decode_header(&hdr_buf, magic)?;
            debug!("received {:?}", msg_hdr.command);

            let mut payload = vec![0u8; msg_hdr.length as usize];
            if msg_hdr.length > 0 {
                stream.read_exact(&mut payload).await?;
            }
            verify_checksum(&msg_hdr, &payload)?;

            match Message::decode(&msg_hdr.command, &payload)
                .map_err(|e| P2pError::DecodeError(e.to_string()))?
            {
                Message::Version(v) => {
                    info!(
                        "peer version={} agent='{}' height={}",
                        v.version, v.user_agent, v.start_height
                    );

                    if v.version < Version::PROTOCOL_VERSION {
                        return Err(P2pError::PeerVersionTooOld {
                            version: v.version as u32,
                            minimum: Version::PROTOCOL_VERSION as u32,
                        });
                    }

                    peer_version = v.version;
                    peer_agent   = v.user_agent;
                    peer_height  = v.start_height;

                    // Send verack
                    let verack_payload = Verack.encode();
                    let verack_header  = encode_header(magic, &Verack::COMMAND, &verack_payload);
                    stream.write_all(&verack_header).await?;
                    debug!("sent verack");
                    got_version = true;
                }

                Message::Verack(_) => {
                    got_verack = true;
                }

                other => debug!("ignoring {} during handshake", other),
            }

            if got_version && got_verack {
                return Ok(());
            }
        }
    })
    .await
    .map_err(|_| P2pError::HandshakeTimeout { secs: 30 })??;

    info!("handshake complete with {}", addr);

    Ok(Connection { stream, magic, peer_version, peer_agent, peer_height })
}