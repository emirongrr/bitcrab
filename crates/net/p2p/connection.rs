//! TCP connection and handshake with a Bitcoin peer.
//!
//! # Handshake sequence (Bitcoin Core: src/net_processing.cpp)
//!
//! Initiator                Responder
//!   ── version ──────────▶
//!   ◀── version ───────────
//!   ── verack ───────────▶
//!   ◀── verack ────────────
//!   [ready]
//!
//! Both sides send version immediately on connect.
//! Both sides send verack after receiving the other's version.

use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tracing::{debug, info};

use super::{
    codec::{decode_header, encode_header, verify_checksum},
    errors::P2pError,
    message::{Command, Magic, VersionMessage},
};
use bitcrab_common::types::hash::BlockHash;
/// A connected peer with a completed handshake.
pub struct Connection {
    pub stream:       TcpStream,
    pub magic:        Magic,
    pub peer_version: i32,
    pub peer_agent:   String,
    pub peer_height:  i32,
}
impl Connection {
    /// Send getheaders and receive up to 2000 headers.
    ///
    /// `locator` — block hashes we already have (most recent first).
    /// Pass `&[BlockHash::ZERO]` or signet genesis to start from the beginning.
    ///
    /// Bitcoin Core: `SendMessages()` → `getheaders` in src/net_processing.cpp
    pub async fn get_headers(
        &mut self,
        locator: &[BlockHash],
    ) -> Result<Vec<bitcrab_common::types::block::BlockHeader>, P2pError> {
        use crate::p2p::codec::{
            decode_headers, encode_getheaders, encode_header, decode_header, verify_checksum,
        };
        use bitcrab_common::types::block::BlockHeader;

        let stop_hash = BlockHash::ZERO; // get as many as possible

        let payload = encode_getheaders(70015, locator, &stop_hash);
        let header  = encode_header(self.magic, &Command::GetHeaders, &payload);

        self.stream.write_all(&header).await?;
        self.stream.write_all(&payload).await?;
        debug!("sent getheaders with {} locator hashes", locator.len());

        // Wait for headers response (ignore other messages)
        loop {
            let mut hdr_buf = [0u8; 24];
            self.stream.read_exact(&mut hdr_buf).await?;
            let msg_hdr = decode_header(&hdr_buf, self.magic)?;

            let mut msg_payload = vec![0u8; msg_hdr.length as usize];
            if msg_hdr.length > 0 {
                self.stream.read_exact(&mut msg_payload).await?;
            }
            verify_checksum(&msg_hdr, &msg_payload)?;

            match msg_hdr.command {
                Command::Headers => {
                    let raw_headers = decode_headers(&msg_payload)?;
                    let count = raw_headers.len();
                    let parsed: Vec<BlockHeader> = raw_headers
                        .into_iter()
                        .map(|b| BlockHeader::deserialize(&b))
                        .collect();
                    info!("received {} headers", count);
                    return Ok(parsed);
                }
                other => {
                    debug!("ignoring {:?} while waiting for headers", other);
                }
            }
        }
    }
}
/// Connect to a peer and complete the Bitcoin handshake.
///
/// Returns a `Connection` ready to send/receive messages.
pub async fn connect(addr: &str, magic: Magic) -> Result<Connection, P2pError> {
    info!("connecting to {}", addr);

    let stream = timeout(
        Duration::from_secs(10),
        TcpStream::connect(addr),
    )
    .await
    .map_err(|_| P2pError::HandshakeTimeout { secs: 10 })?
    .map_err(P2pError::Io)?;

    info!("TCP connected to {}", addr);

    handshake(stream, magic, addr).await
}

/// Run the version/verack handshake on an established TCP stream.
async fn handshake(
    mut stream: TcpStream,
    magic: Magic,
    addr: &str,
) -> Result<Connection, P2pError> {
    // Send our version message
    let version_payload = encode_version_payload();
    let header = encode_header(magic, &Command::Version, &version_payload);
    stream.write_all(&header).await?;
    stream.write_all(&version_payload).await?;
    debug!("sent version");

    let mut peer_version = 0i32;
    let mut peer_agent   = String::new();
    let mut peer_height  = 0i32;
    let mut got_version  = false;
    let mut got_verack   = false;

    // Wait for version + verack from peer (with timeout)
    timeout(Duration::from_secs(30), async {
        loop {
            // Read 24-byte header
            let mut header_buf = [0u8; 24];
            stream.read_exact(&mut header_buf).await?;

            let msg_header = decode_header(&header_buf, magic)?;
            debug!("received {:?}", msg_header.command);

            // Read payload
            let mut payload = vec![0u8; msg_header.length as usize];
            if msg_header.length > 0 {
                stream.read_exact(&mut payload).await?;
            }

            // Verify checksum
            verify_checksum(&msg_header, &payload)?;

            match msg_header.command {
                Command::Version => {
                    // Parse peer's version
                    (peer_version, peer_agent, peer_height) =
                        parse_version_payload(&payload);

                    info!(
                        "peer version={} agent='{}' height={}",
                        peer_version, peer_agent, peer_height
                    );

                    if peer_version < VersionMessage::CURRENT_VERSION {
                        return Err(P2pError::PeerVersionTooOld {
                            version: peer_version as u32,
                            minimum: VersionMessage::CURRENT_VERSION as u32,
                        });
                    }

                    // Send verack in response to their version
                    let verack_header =
                        encode_header(magic, &Command::Verack, b"");
                    stream.write_all(&verack_header).await?;
                    debug!("sent verack");

                    got_version = true;
                }

                Command::Verack => {
                    got_verack = true;
                }

                // Ignore other messages during handshake
                other => {
                    debug!("ignoring {:?} during handshake", other);
                }
            }

            if got_version && got_verack {
                return Ok(());
            }
        }
    })
    .await
    .map_err(|_| P2pError::HandshakeTimeout { secs: 30 })??;

    info!("handshake complete with {}", addr);

    Ok(Connection {
        stream,
        magic,
        peer_version,
        peer_agent,
        peer_height,
    })
}

/// Encode our version message payload.
///
/// Bitcoin wire format for version payload:
/// version(4) services(8) timestamp(8)
/// recv_services(8) recv_addr(16) recv_port(2)
/// from_services(8) from_addr(16) from_port(2)
/// nonce(8) user_agent(varint+str) start_height(4) relay(1)
///
/// Bitcoin Core: src/net_processing.cpp `PushMessage(peer, NetMsgType::VERSION, ...)`
fn encode_version_payload() -> Vec<u8> {
    let mut buf = Vec::new();

    // version
    buf.extend_from_slice(&VersionMessage::CURRENT_VERSION.to_le_bytes());

    // services — NODE_NETWORK | NODE_WITNESS
    buf.extend_from_slice(&VersionMessage::SERVICES.to_le_bytes());

    // timestamp
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    buf.extend_from_slice(&now.to_le_bytes());

    // recv_services, recv_addr, recv_port (we don't know these yet)
    buf.extend_from_slice(&0u64.to_le_bytes()); // recv_services
    buf.extend_from_slice(&[0u8; 16]);           // recv_addr
    buf.extend_from_slice(&0u16.to_be_bytes());  // recv_port (big-endian in wire format)

    // from_services, from_addr, from_port
    buf.extend_from_slice(&VersionMessage::SERVICES.to_le_bytes());
    buf.extend_from_slice(&[0u8; 16]);
    buf.extend_from_slice(&0u16.to_be_bytes());

    // nonce — random u64 to detect self-connections
    let nonce: u64 = rand_nonce();
    buf.extend_from_slice(&nonce.to_le_bytes());

    // user agent — varint length + bytes
    let ua = VersionMessage::USER_AGENT.as_bytes();
    buf.push(ua.len() as u8); // varint (single byte sufficient for short UA)
    buf.extend_from_slice(ua);

    // start_height — we have no blocks yet
    buf.extend_from_slice(&0i32.to_le_bytes());

    // relay — true
    buf.push(1u8);

    buf
}

/// Parse the fields we care about from a peer's version payload.
/// Returns (version, user_agent, start_height).
fn parse_version_payload(payload: &[u8]) -> (i32, String, i32) {
    if payload.len() < 20 {
        return (0, String::new(), 0);
    }

    let version = i32::from_le_bytes(payload[0..4].try_into().unwrap());

    // Skip: services(8) timestamp(8) = 16 bytes
    // Skip: recv_services(8) recv_addr(16) recv_port(2) = 26 bytes
    // Skip: from_services(8) from_addr(16) from_port(2) = 26 bytes
    // Skip: nonce(8) = 8 bytes
    // Total to skip after version: 4 + 16 + 26 + 26 + 8 = 80... let's be safe
    let offset = 4 + 8 + 8 + 8 + 16 + 2 + 8 + 16 + 2 + 8;

    if payload.len() <= offset {
        return (version, String::new(), 0);
    }

    // user agent varint + string
    let ua_len = payload[offset] as usize;
    let ua_start = offset + 1;
    let ua_end = ua_start + ua_len;

    if payload.len() < ua_end + 4 {
        return (version, String::new(), 0);
    }

    let user_agent = String::from_utf8_lossy(&payload[ua_start..ua_end]).to_string();

    let start_height =
        i32::from_le_bytes(payload[ua_end..ua_end + 4].try_into().unwrap());

    (version, user_agent, start_height)
}

/// Simple non-cryptographic nonce for self-connection detection.
fn rand_nonce() -> u64 {
    // Use current time + pointer trick as cheap nonce
    // Good enough for self-connection detection, not for security
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos() as u64
        | 0xDEAD_BEEF_0000_0000
}