//! Bitcoin P2P messages.
//!
//! Each message type implements `BitcoinMessage` — it knows its own
//! command and handles its own encode/decode using `Encoder`/`Decoder`.
//!

pub mod getheaders;
pub mod headers;
pub mod ping;
pub mod verack;
pub mod version;

use bitcrab_common::wire::DecodeError;
pub use getheaders::GetHeaders;
pub use headers::Headers;
pub use ping::{Ping, Pong};
pub use verack::Verack;
pub use version::Version;

use crate::p2p::{message::Command};

/// A Bitcoin P2P message.
///
/// Each implementor knows its command name and serializes/deserializes
/// its own payload. The 24-byte header framing is handled separately
/// in `codec.rs`.
///
pub trait BitcoinMessage: Sized {
    /// The wire command name for this message type.
    const COMMAND: Command;

    /// Encode the message payload (excluding the 24-byte header).
    fn encode(&self) -> Vec<u8>;

    /// Decode from raw payload bytes.
    fn decode(payload: &[u8]) -> Result<Self, DecodeError>;
}

/// All supported inbound P2P messages.
///
#[derive(Debug, Clone)]
pub enum Message {
    Version(Version),
    Verack(Verack),
    Ping(Ping),
    Pong(Pong),
    GetHeaders(GetHeaders),
    Headers(Headers),
    /// Received a known command we don't handle yet.
    Ignored(Command),
    /// Received an unknown command.
    Unknown(String),
}

impl Message {
    /// Decode a message from its command and raw payload.
    ///
    pub fn decode(command: &Command, payload: &[u8]) -> Result<Self, DecodeError> {
        match command {
            Command::Version     => Ok(Self::Version(Version::decode(payload)?)),
            Command::Verack      => Ok(Self::Verack(Verack::decode(payload)?)),
            Command::Ping        => Ok(Self::Ping(Ping::decode(payload)?)),
            Command::Pong        => Ok(Self::Pong(Pong::decode(payload)?)),
            Command::GetHeaders  => Ok(Self::GetHeaders(GetHeaders::decode(payload)?)),
            Command::Headers     => Ok(Self::Headers(Headers::decode(payload)?)),
            other                => Ok(Self::Ignored(other.clone())),
        }
    }
}

impl std::fmt::Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Version(_)    => write!(f, "version"),
            Self::Verack(_)     => write!(f, "verack"),
            Self::Ping(_)       => write!(f, "ping"),
            Self::Pong(_)       => write!(f, "pong"),
            Self::GetHeaders(_) => write!(f, "getheaders"),
            Self::Headers(_)    => write!(f, "headers"),
            Self::Ignored(c)    => write!(f, "ignored({:?})", c),
            Self::Unknown(s)    => write!(f, "unknown({})", s),
        }
    }
}