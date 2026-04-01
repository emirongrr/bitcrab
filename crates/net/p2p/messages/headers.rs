//! Headers message — response to getheaders.
//!
//! Each entry: 80-byte header + 0x00 (empty tx count varint).
//! Bitcoin Core: MAX_HEADERS_RESULTS = 2000

use bitcrab_common::types::block::BlockHeader;
use crate::p2p::{message::Command, wire::{DecodeError, Decoder, Encoder}};
use super::BitcoinMessage;

#[derive(Debug, Clone)]
pub struct Headers {
    pub headers: Vec<BlockHeader>,
}

impl BitcoinMessage for Headers {
    const COMMAND: Command = Command::Headers;

    fn encode(&self) -> Vec<u8> {
        let mut enc = Encoder::new().write_varint(self.headers.len() as u64);
        for h in &self.headers {
            enc = enc.write_bytes(&h.serialize()).write_u8(0x00);
        }
        enc.finish()
    }

    fn decode(p: &[u8]) -> Result<Self, DecodeError> {
        if p.is_empty() {
            return Ok(Self { headers: vec![] });
        }
        let dec = Decoder::new(p);
        let (count, mut dec) = dec.read_varint("header_count")?;
        let mut headers = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let (raw, d) = dec.read_array::<80>("header")?;
            let (_tx_count, d) = d.read_u8("tx_count")?;
            headers.push(BlockHeader::deserialize(&raw));
            dec = d;
        }
        dec.finish_unchecked();
        Ok(Self { headers })
    }
}