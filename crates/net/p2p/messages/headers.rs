//! Headers message — response to getheaders.
//!
//! Bitcoin Core: NetMsgType::HEADERS in src/protocol.h
//! Each entry: 80-byte header + 0x00 varint (empty tx count).
//!
//! Bitcoin Core: MAX_HEADERS_RESULTS = 2000 in src/net_processing.cpp

use super::BitcoinMessage;
use crate::p2p::message::Command;
use bitcrab_common::{
    constants::MAX_HEADERS_PER_MSG,
    types::block::BlockHeader,
    wire::{encode::VarInt, error::DecodeError, Decoder, Encoder},
};

#[derive(Debug, Clone)]
pub struct Headers {
    pub headers: Vec<BlockHeader>,
}

impl BitcoinMessage for Headers {
    const COMMAND: Command = Command::Headers;

    fn encode(&self) -> Vec<u8> {
        let mut enc = Encoder::new().encode_field(&VarInt(self.headers.len() as u64));
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
        if count as usize > MAX_HEADERS_PER_MSG {
            return Err(DecodeError::AllocationTooLarge {
                field: "header_count",
                len: count,
                limit: MAX_HEADERS_PER_MSG,
            });
        }
        let mut headers = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let (raw, d) = dec.read_array::<80>("header")?;
            let (tx_count, d) = d.decode_field::<u8>("tx_count")?;
            if tx_count != 0 {
                return Err(DecodeError::InvalidValue {
                    field: "tx_count",
                    value: tx_count as u64,
                });
            }
            headers.push(BlockHeader::deserialize(&raw));
            dec = d;
        }
        dec.finish("headers")?;
        Ok(Self { headers })
    }
}
