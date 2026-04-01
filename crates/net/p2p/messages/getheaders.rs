//! GetHeaders message.
//!
//! Bitcoin Core: NetMsgType::GETHEADERS in src/protocol.h
//! Wire: version(4LE) locator_count(varint) hashes(32×n) stop_hash(32)
//!
//! Bitcoin Core: ProcessGetHeaders() in src/net_processing.cpp

use bitcrab_common::{
    types::hash::BlockHash,
    wire::{Decoder, Encoder, encode::{VarInt}, error::DecodeError},
};
use crate::p2p::message::Command;

use super::BitcoinMessage;

/// Request up to 2000 headers from the peer's chain.
///
/// The locator is a list of hashes we already have — peer finds the
/// highest common ancestor and sends from there.
///
/// Bitcoin Core: CBlockLocator in src/primitives/block.h
#[derive(Debug, Clone)]
pub struct GetHeaders {
    /// Protocol version.
    /// Bitcoin Core: nVersion field in getheaders
    pub version:   u32,
    /// Hashes we have, most recent first.
    pub locator:   Vec<BlockHash>,
    /// All-zeros = get as many as possible (up to 2000).
    /// Bitcoin Core: MAX_HEADERS_RESULTS = 2000 in src/net_processing.cpp
    pub stop_hash: BlockHash,
}

impl GetHeaders {
    pub fn from_tip(tip: BlockHash) -> Self {
        Self {
            version:   70015,
            locator:   vec![tip],
            stop_hash: BlockHash::ZERO,
        }
    }
}

impl BitcoinMessage for GetHeaders {
    const COMMAND: Command = Command::GetHeaders;

    fn encode(&self) -> Vec<u8> {
        let mut enc = Encoder::new()
            .encode_field(&self.version)
            .encode_field(&VarInt(self.locator.len() as u64));
        for hash in &self.locator {
            enc = enc.encode_field(hash.as_bytes());
        }
        enc.encode_field(self.stop_hash.as_bytes()).finish()
    }

    fn decode(payload: &[u8]) -> Result<Self, DecodeError> {
        let dec = Decoder::new(payload);
        let (version,       dec) = dec.decode_field("version")?;
        let (count,         dec) = dec.read_varint("locator_count")?;
        let mut dec = dec;
        let mut locator = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let (bytes, d) = dec.read_array::<32>("locator_hash")?;
            locator.push(BlockHash::from_bytes(bytes));
            dec = d;
        }
        let (stop, dec) = dec.read_array::<32>("stop_hash")?;
        dec.finish_unchecked();
        Ok(Self { version, locator, stop_hash: BlockHash::from_bytes(stop) })
    }
}