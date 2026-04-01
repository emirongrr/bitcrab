//! GetHeaders message.
//!
//! Bitcoin Core: src/net_processing.cpp `ProcessGetHeaders()`
//! Wire: version(4LE) locator_count(varint) hashes(32×n) stop_hash(32)

use bitcrab_common::types::hash::BlockHash;
use crate::p2p::{message::Command, wire::{DecodeError, Decoder, Encoder}};
use super::BitcoinMessage;

#[derive(Debug, Clone)]
pub struct GetHeaders {
    pub version:   u32,
    pub locator:   Vec<BlockHash>,
    pub stop_hash: BlockHash,
}

impl GetHeaders {
    pub fn from_tip(tip: BlockHash) -> Self {
        Self { version: 70015, locator: vec![tip], stop_hash: BlockHash::ZERO }
    }
}

impl BitcoinMessage for GetHeaders {
    const COMMAND: Command = Command::GetHeaders;

    fn encode(&self) -> Vec<u8> {
        let mut enc = Encoder::new()
            .write_u32_le(self.version)
            .write_varint(self.locator.len() as u64);
        for hash in &self.locator {
            enc = enc.write_bytes(hash.as_bytes());
        }
        enc.write_bytes(self.stop_hash.as_bytes()).finish()
    }

    fn decode(p: &[u8]) -> Result<Self, DecodeError> {
        let dec = Decoder::new(p);
        let (version, dec)      = dec.read_u32_le("version")?;
        let (count,   dec)      = dec.read_varint("locator_count")?;
        let mut locator = Vec::with_capacity(count as usize);
        let mut dec = dec;
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