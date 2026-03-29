//! Bitcoin P2P message types.
//!
//! # Wire format
//!
//! Every message has a 24-byte header:
//!
//! ```text
//! magic      4 bytes  — network identifier
//! command   12 bytes  — ASCII, null-padded
//! length     4 bytes  — payload size (little-endian u32)
//! checksum   4 bytes  — first 4 bytes of hash256(payload)
//! ```
//!
//! Followed by `length` bytes of payload.
//!
//! Bitcoin Core: `CMessageHeader` in src/protocol.h

/// Network magic bytes — identifies which Bitcoin network a node is on.
///
/// Bitcoin Core: `MessageStartChars` in src/protocol.h
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Magic {
    /// Main network.
    /// Bitcoin Core: `pchMessageStart` in src/kernel/chainparams.cpp
    Mainnet,
    /// Test network 3.
    Testnet3,
    /// Signet (BIP-325) — our default for development.
    Signet,
    /// Regression test — local only.
    Regtest,
}

impl Magic {
    /// 4-byte magic value for this network.
    pub fn to_bytes(self) -> [u8; 4] {
        match self {
            Magic::Mainnet  => [0xF9, 0xBE, 0xB4, 0xD9],
            Magic::Testnet3 => [0x0B, 0x11, 0x09, 0x07],
            Magic::Signet   => [0x0A, 0x03, 0xCF, 0x40],
            Magic::Regtest  => [0xFA, 0xBF, 0xB5, 0xDA],
        }
    }

    /// Parse magic from 4 bytes. Returns None if unknown.
    pub fn from_bytes(b: [u8; 4]) -> Option<Self> {
        match b {
            [0xF9, 0xBE, 0xB4, 0xD9] => Some(Magic::Mainnet),
            [0x0B, 0x11, 0x09, 0x07] => Some(Magic::Testnet3),
            [0x0A, 0x03, 0xCF, 0x40] => Some(Magic::Signet),
            [0xFA, 0xBF, 0xB5, 0xDA] => Some(Magic::Regtest),
            _ => None,
        }
    }
}

/// Parsed 24-byte message header.
///
/// Bitcoin Core: `CMessageHeader` in src/protocol.h
#[derive(Debug, Clone)]
pub struct MessageHeader {
    pub magic:    Magic,
    /// Command name — "version", "verack", "ping", etc.
    pub command:  Command,
    /// Payload length in bytes.
    pub length:   u32,
    /// First 4 bytes of hash256(payload).
    pub checksum: [u8; 4],
}

/// Known P2P command names.
///
/// Bitcoin Core: command strings in src/protocol.cpp
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
    /// A command we don't handle yet — stored as raw string.
    Unknown(String),
}

impl Command {
    /// Parse from the 12-byte null-padded wire representation.
    pub fn from_wire(bytes: &[u8; 12]) -> Self {
        // Trim null bytes
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(12);
        let s = std::str::from_utf8(&bytes[..end]).unwrap_or("");
        match s {
            "version"     => Command::Version,
            "verack"      => Command::Verack,
            "ping"        => Command::Ping,
            "pong"        => Command::Pong,
            "getheaders"  => Command::GetHeaders,
            "headers"     => Command::Headers,
            "getdata"     => Command::GetData,
            "inv"         => Command::Inv,
            "getblocks"   => Command::GetBlocks,
            "block"       => Command::Block,
            "tx"          => Command::Tx,
            "addr"        => Command::Addr,
            "getaddr"     => Command::GetAddr,
            "sendheaders" => Command::SendHeaders,
            "feefilter"   => Command::FeeFilter,
            "sendcmpct"   => Command::SendCmpct,
            other         => Command::Unknown(other.to_string()),
        }
    }

    /// Encode to the 12-byte null-padded wire representation.
    pub fn to_wire(&self) -> [u8; 12] {
        let s = match self {
            Command::Version     => "version",
            Command::Verack      => "verack",
            Command::Ping        => "ping",
            Command::Pong        => "pong",
            Command::GetHeaders  => "getheaders",
            Command::Headers     => "headers",
            Command::GetData     => "getdata",
            Command::Inv         => "inv",
            Command::GetBlocks   => "getblocks",
            Command::Block       => "block",
            Command::Tx          => "tx",
            Command::Addr        => "addr",
            Command::GetAddr     => "getaddr",
            Command::SendHeaders => "sendheaders",
            Command::FeeFilter   => "feefilter",
            Command::SendCmpct   => "sendcmpct",
            Command::Unknown(s)  => s.as_str(),
        };
        let mut buf = [0u8; 12];
        let bytes = s.as_bytes();
        let len = bytes.len().min(12);
        buf[..len].copy_from_slice(&bytes[..len]);
        buf
    }
}

/// Version message payload.
///
/// Sent by both sides at the start of every connection.
/// Bitcoin Core: `CVersionMessage` in src/protocol.h
#[derive(Debug, Clone)]
pub struct VersionMessage {
    /// Protocol version we support.
    /// Bitcoin Core: `PROTOCOL_VERSION = 70015`
    pub version:      i32,
    /// Services we offer (NODE_NETWORK=1, NODE_WITNESS=8).
    pub services:     u64,
    /// Our current unix timestamp.
    pub timestamp:    i64,
    /// Receiver's services (can be 0 — we don't know yet).
    pub recv_services: u64,
    /// Receiver's IP (16 bytes, IPv6 or IPv4-mapped).
    pub recv_addr:    [u8; 16],
    pub recv_port:    u16,
    /// Our services again.
    pub from_services: u64,
    /// Our IP.
    pub from_addr:    [u8; 16],
    pub from_port:    u16,
    /// Random nonce — detects self-connections.
    pub nonce:        u64,
    /// "/bitcrab:0.1.0/" style user agent (BIP-14).
    pub user_agent:   String,
    /// Our best chain height.
    pub start_height: i32,
    /// Whether we want tx relay (true by default).
    pub relay:        bool,
}

impl VersionMessage {
    pub const CURRENT_VERSION: i32 = 70015;
    pub const USER_AGENT: &'static str = "/bitcrab:0.1.0/";

    /// NODE_NETWORK | NODE_WITNESS
    pub const SERVICES: u64 = 0x09;
}