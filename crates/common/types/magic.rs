//! Bitcoin P2P message-start bytes.

use crate::wire::{
    decode::{BitcoinDecode, Decoder},
    encode::{BitcoinEncode, Encoder},
    error::DecodeError,
};

/// Bitcoin P2P message-start bytes.
///
/// Bitcoin Core: `MessageStartChars` / `pchMessageStart`.
/// These bytes are often called "magic bytes" informally, but they are
/// not the chain selector itself; `ChainType` selects the active chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Magic(pub [u8; 4]);

/// Bitcoin Core naming alias for P2P message-start bytes.
pub type MessageStartChars = Magic;

impl Magic {
    pub const MAINNET: Self = Self([0xF9, 0xBE, 0xB4, 0xD9]);
    pub const TESTNET3: Self = Self([0x0B, 0x11, 0x09, 0x07]);
    pub const SIGNET: Self = Self([0x0A, 0x03, 0xCF, 0x40]);
    pub const REGTEST: Self = Self([0xFA, 0xBF, 0xB5, 0xDA]);

    /// Get the 4-byte wire representation of the message-start bytes.
    pub const fn to_bytes(self) -> [u8; 4] {
        self.0
    }

    /// Parse a 4-byte array into message-start bytes.
    pub const fn from_bytes(b: [u8; 4]) -> Self {
        Self(b)
    }

    /// Derives Signet message-start bytes from the challenge script.
    /// MessageStart = sha256d(compact_size(challenge_script.len()) + challenge_script)[0..4]
    pub fn from_signet_challenge(challenge: &[u8]) -> Self {
        use crate::types::hash::hash256;
        use crate::wire::encode::VarBytes;

        // Signet magic is the first 4 bytes of sha256d of the challenge script
        // as a single data push (length-prefixed).
        let buffer = Encoder::new().encode_field(&VarBytes(challenge)).finish();

        let hash = hash256(&buffer);
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&hash[0..4]);
        Self(magic)
    }
}

impl BitcoinEncode for Magic {
    fn encode(&self, enc: Encoder) -> Encoder {
        enc.encode_field(&self.0)
    }
}

impl BitcoinDecode for Magic {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        let (bytes, dec) = dec.decode_field::<[u8; 4]>("magic")?;
        Ok((Self(bytes), dec))
    }
}

impl Default for Magic {
    fn default() -> Self {
        Self::MAINNET
    }
}

impl std::fmt::Display for Magic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::MAINNET => write!(f, "mainnet"),
            Self::TESTNET3 => write!(f, "testnet3"),
            Self::SIGNET => write!(f, "signet"),
            Self::REGTEST => write!(f, "regtest"),
            _ => write!(f, "custom({:02X?})", self.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signet_magic() {
        let challenge_hex = "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae";
        let challenge = hex::decode(challenge_hex).unwrap();
        let magic = Magic::from_signet_challenge(&challenge);
        assert_eq!(magic.to_bytes(), [0x0A, 0x03, 0xCF, 0x40]);
    }
}
