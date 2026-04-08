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
pub mod addr;

use bitcrab_common::wire::DecodeError;
pub use getheaders::GetHeaders;
pub use headers::Headers;
pub use ping::{Ping, Pong};
pub use verack::Verack;
pub use version::Version;
pub use addr::{Addr, GetAddr, NetAddr};

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
    Addr(Addr),
    GetAddr(GetAddr),
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
            Command::Addr        => Ok(Self::Addr(Addr::decode(payload)?)),
            Command::GetAddr     => Ok(Self::GetAddr(GetAddr::decode(payload)?)),
            other                => Ok(Self::Ignored(other.clone())),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Version(v)    => v.encode(),
            Self::Verack(v)     => v.encode(),
            Self::Ping(v)       => v.encode(),
            Self::Pong(v)       => v.encode(),
            Self::GetHeaders(v) => v.encode(),
            Self::Headers(v)    => v.encode(),
            Self::Addr(v)       => v.encode(),
            Self::GetAddr(v)    => v.encode(),
            _ => vec![],
        }
    }

    pub fn command(&self) -> Command {
        match self {
            Self::Version(_)    => Command::Version,
            Self::Verack(_)     => Command::Verack,
            Self::Ping(_)       => Command::Ping,
            Self::Pong(_)       => Command::Pong,
            Self::GetHeaders(_) => Command::GetHeaders,
            Self::Headers(_)    => Command::Headers,
            Self::Addr(_)       => Command::Addr,
            Self::GetAddr(_)    => Command::GetAddr,
            Self::Ignored(c)    => c.clone(),
            Self::Unknown(s)    => Command::Unknown(s.clone()),
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
            Self::Addr(_)       => write!(f, "addr"),
            Self::GetAddr(_)    => write!(f, "getaddr"),
            Self::Ignored(c)    => write!(f, "ignored({:?})", c),
            Self::Unknown(s)    => write!(f, "unknown({})", s),
        }
    }
}