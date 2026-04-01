//! Headers message — response to getheaders.
//!
//! Bitcoin Core: NetMsgType::HEADERS in src/protocol.h
//! Each entry: 80-byte header + 0x00 varint (empty tx count).
//!
//! Bitcoin Core: MAX_HEADERS_RESULTS = 2000 in src/net_processing.cpp

use bitcrab_common::{
    types::block::BlockHeader,
    wire::{Decoder, Encoder, encode::VarInt, error::DecodeError},
};
use crate::p2p::message::Command;
use super::BitcoinMessage;

#[derive(Debug, Clone)]
pub struct Headers {
    pub headers: Vec<BlockHeader>,
}

impl BitcoinMessage for Headers {
    const COMMAND: Command = Command::Headers;

    fn encode(&self) -> Vec<u8> {
        let mut enc = Encoder::new()
            .encode_field(&VarInt(self.headers.len() as u64));
        for h in &self.headers {
            // 80 bytes + 0x00 tx count
            enc = enc.encode_field(&h.serialize()).encode_field(&0u8);
        }
        enc.finish()
    }

    fn decode(payload: &[u8]) -> Result<Self, DecodeError> {
        if payload.is_empty() {
            return Ok(Self { headers: vec![] });
        }
        let dec = Decoder::new(payload);
        let (count, mut dec) = dec.read_varint("header_count")?;
        let mut headers = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let (raw, d)      = dec.read_array::<80>("header")?;
            let (_tx_count, d) = d.decode_field::<u8>("tx_count")?;
            headers.push(BlockHeader::deserialize(&raw));
            dec = d;
        }
        dec.finish_unchecked();
        Ok(Self { headers })
    }
}