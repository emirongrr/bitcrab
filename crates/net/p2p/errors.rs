//! P2P network errors.
//!
//! Only errors that actually occur in the P2P layer.
//! No speculative error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum P2pError {
    /// TCP connection failed.
    #[error("connection failed to {addr}: {reason}")]
    ConnectionFailed { addr: String, reason: String },

    /// Peer sent a message with wrong network magic bytes.
    /// This means we connected to a node on a different network.
    ///
    /// Bitcoin Core: checked in `CNode::ReceiveMsgBytes()`
    #[error("wrong magic: expected {expected:#010x}, got {actual:#010x}")]
    WrongMagic { expected: u32, actual: u32 },

    /// Message payload is larger than MAX_MESSAGE_SIZE (32 MB).
    ///
    /// Bitcoin Core: `MAX_PROTOCOL_MESSAGE_LENGTH` check
    #[error("message too large: {size} bytes exceeds limit {limit}")]
    MessageTooLarge { size: u32, limit: usize },

    /// Payload checksum did not match header checksum.
    ///
    /// Bitcoin Core: `CNetMessage::readHeader()` checksum check
    #[error("checksum mismatch: expected {expected:#010x}, got {actual:#010x}")]
    ChecksumMismatch { expected: u32, actual: u32 },

    /// Peer closed the connection unexpectedly.
    #[error("connection closed by peer")]
    ConnectionClosed,

    /// Handshake did not complete within the timeout.
    #[error("handshake timeout after {secs}s")]
    HandshakeTimeout { secs: u64 },

    /// Peer sent a version below our minimum.
    ///
    /// Bitcoin Core: `MIN_PEER_PROTO_VERSION` check in `net_processing.cpp`
    #[error("peer version {version} is below minimum {minimum}")]
    PeerVersionTooOld { version: i32, minimum: i32 },

    /// IO error from the underlying TCP stream.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Message decode failed.
    #[error("decode error: {0}")]
    DecodeError(String),

    /// Detected a connection to ourselves via nonce matching.
    ///
    /// Bitcoin Core: nonce check in src/net.cpp
    #[error("self-connection detected — disconnecting")]
    SelfConnection,

    /// Peer is banned due to misbehavior.
    #[error("peer is banned")]
    Banned,
}
