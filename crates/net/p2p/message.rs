//! Bitcoin P2P wire protocol — network magic and command types.
//!
//! Bitcoin Core: src/protocol.h

/// Network magic bytes — identifies which Bitcoin network.
///
/// Bitcoin Core: MessageStartChars in src/protocol.h
pub use bitcrab_common::Magic;

use crate::p2p::errors::P2pError;

/// P2P message command names.
///
/// Bitcoin Core: NetMsgType constants in src/protocol.h
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Version,
    Verack,
    Ping,
    Pong,
    GetHeaders,
    Headers,
    GetData,
    Inv,
    GetBlocks,
    Block,
    Tx,
    Addr,
    GetAddr,
    SendHeaders,
    FeeFilter,
    SendCmpct,
    NotFound,
    Unknown(String),
}

impl Command {
    pub fn from_wire(bytes: &[u8; 12]) -> Result<Self, P2pError> {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(12);
        if end == 0 {
            return Err(P2pError::MalformedCommand {
                bytes: *bytes,
                reason: "empty command",
            });
        }
        if bytes[end..].iter().any(|&b| b != 0) {
            return Err(P2pError::MalformedCommand {
                bytes: *bytes,
                reason: "non-null byte after command terminator",
            });
        }
        if bytes[..end].iter().any(|&b| !(0x20..=0x7e).contains(&b)) {
            return Err(P2pError::MalformedCommand {
                bytes: *bytes,
                reason: "command contains non-printable ascii",
            });
        }

        let s = std::str::from_utf8(&bytes[..end]).map_err(|_| P2pError::MalformedCommand {
            bytes: *bytes,
            reason: "command is not utf-8",
        })?;
        Ok(match s {
            "version" => Command::Version,
            "verack" => Command::Verack,
            "ping" => Command::Ping,
            "pong" => Command::Pong,
            "getheaders" => Command::GetHeaders,
            "headers" => Command::Headers,
            "getdata" => Command::GetData,
            "inv" => Command::Inv,
            "getblocks" => Command::GetBlocks,
            "block" => Command::Block,
            "tx" => Command::Tx,
            "addr" => Command::Addr,
            "getaddr" => Command::GetAddr,
            "sendheaders" => Command::SendHeaders,
            "feefilter" => Command::FeeFilter,
            "sendcmpct" => Command::SendCmpct,
            "notfound" => Command::NotFound,
            other => Command::Unknown(other.to_string()),
        })
    }

    pub fn to_wire(&self) -> [u8; 12] {
        let mut buf = [0u8; 12];
        let s = self.name().as_bytes();
        let len = s.len().min(12);
        buf[..len].copy_from_slice(&s[..len]);
        buf
    }

    pub fn name(&self) -> &str {
        match self {
            Command::Version => "version",
            Command::Verack => "verack",
            Command::Ping => "ping",
            Command::Pong => "pong",
            Command::GetHeaders => "getheaders",
            Command::Headers => "headers",
            Command::GetData => "getdata",
            Command::Inv => "inv",
            Command::GetBlocks => "getblocks",
            Command::Block => "block",
            Command::Tx => "tx",
            Command::Addr => "addr",
            Command::GetAddr => "getaddr",
            Command::SendHeaders => "sendheaders",
            Command::FeeFilter => "feefilter",
            Command::SendCmpct => "sendcmpct",
            Command::NotFound => "notfound",
            Command::Unknown(s) => s.as_str(),
        }
    }
}

/// Decoded 24-byte message header.
///
/// Bitcoin Core: CMessageHeader in src/protocol.h
#[derive(Debug, Clone)]
pub struct MessageHeader {
    pub magic: Magic,
    pub command: Command,
    pub length: u32,
    pub checksum: [u8; 4],
}
