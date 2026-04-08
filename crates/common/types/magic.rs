//! Bitcoin network magic bytes.

use crate::wire::{
    decode::{BitcoinDecode, Decoder},
    encode::{BitcoinEncode, Encoder},
    error::DecodeError,
};

/// Network magic bytes — identifies which Bitcoin network.
///
/// Bitcoin Core: MessageStartChars in src/protocol.h
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Magic {
    Mainnet,
    Testnet3,
    Signet,
    Regtest,
}

impl Magic {
    /// Get the 4-byte wire representation of the network magic.
    pub const fn to_bytes(self) -> [u8; 4] {
        match self {
            Magic::Mainnet => [0xF9, 0xBE, 0xB4, 0xD9],
            Magic::Testnet3 => [0x0B, 0x11, 0x09, 0x07],
            Magic::Signet => [0x0A, 0x03, 0xCF, 0x40],
            Magic::Regtest => [0xFA, 0xBF, 0xB5, 0xDA],
        }
    }

    /// Parse a 4-byte array into a known network magic.
    pub const fn from_bytes(b: [u8; 4]) -> Option<Self> {
        // Match cannot use const arrays directly in some Rust versions, but these are small literal patterns.
        match b {
            [0xF9, 0xBE, 0xB4, 0xD9] => Some(Magic::Mainnet),
            [0x0B, 0x11, 0x09, 0x07] => Some(Magic::Testnet3),
            [0x0A, 0x03, 0xCF, 0x40] => Some(Magic::Signet),
            [0xFA, 0xBF, 0xB5, 0xDA] => Some(Magic::Regtest),
            _ => None,
        }
    }
}

impl BitcoinEncode for Magic {
    fn encode(&self, enc: Encoder) -> Encoder {
        enc.encode_field(&self.to_bytes())
    }
}

impl BitcoinDecode for Magic {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        let (bytes, dec) = dec.decode_field::<[u8; 4]>("magic")?;
        let magic = Self::from_bytes(bytes)
            .ok_or_else(|| DecodeError::Custom(format!("unknown network magic: {:02X?}", bytes)))?;
        Ok((magic, dec))
    }
}

impl Default for Magic {
    fn default() -> Self {
        Self::Mainnet
    }
}

impl std::fmt::Display for Magic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Magic::Mainnet => "mainnet",
            Magic::Testnet3 => "testnet3",
            Magic::Signet => "signet",
            Magic::Regtest => "regtest",
        };
        write!(f, "{}", name)
    }
}
