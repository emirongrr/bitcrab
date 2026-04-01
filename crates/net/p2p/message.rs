//! Bitcoin P2P wire protocol — network magic and command types.
//!
//! Bitcoin Core: src/protocol.h

/// Network magic bytes — identifies which Bitcoin network.
///
/// Bitcoin Core: MessageStartChars in src/protocol.h
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Magic {
    Mainnet,
    Testnet3,
    Signet,
    Regtest,
}

impl Magic {
    pub fn to_bytes(self) -> [u8; 4] {
        match self {
            Magic::Mainnet  => [0xF9, 0xBE, 0xB4, 0xD9],
            Magic::Testnet3 => [0x0B, 0x11, 0x09, 0x07],
            Magic::Signet   => [0x0A, 0x03, 0xCF, 0x40],
            Magic::Regtest  => [0xFA, 0xBF, 0xB5, 0xDA],
        }
    }

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
    Unknown(String),
}

impl Command {
    pub fn from_wire(bytes: &[u8; 12]) -> Self {
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

    pub fn to_wire(&self) -> [u8; 12] {
        let mut buf = [0u8; 12];
        let s = self.name().as_bytes();
        let len = s.len().min(12);
        buf[..len].copy_from_slice(&s[..len]);
        buf
    }

    pub fn name(&self) -> &str {
        match self {
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
        }
    }
}

/// Decoded 24-byte message header.
///
/// Bitcoin Core: CMessageHeader in src/protocol.h
#[derive(Debug, Clone)]
pub struct MessageHeader {
    pub magic:    Magic,
    pub command:  Command,
    pub length:   u32,
    pub checksum: [u8; 4],
}