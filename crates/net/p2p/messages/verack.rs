//! Verack — acknowledges a version message. Zero-byte payload.
//!
//! Bitcoin Core: NetMsgType::VERACK in src/protocol.h

use super::BitcoinMessage;
use crate::p2p::message::Command;
use bitcrab_common::wire::{
    decode_exact, error::DecodeError, BitcoinDecode, BitcoinEncode, Decoder, Encoder,
};

#[derive(Debug, Clone)]
pub struct Verack;

impl BitcoinMessage for Verack {
    const COMMAND: Command = Command::Verack;

    fn encode(&self) -> Vec<u8> {
        Encoder::new().encode_field(self).finish()
    }

    fn decode(payload: &[u8]) -> Result<Self, DecodeError> {
        decode_exact::<Self>(payload, "verack")
    }
}

impl BitcoinEncode for Verack {
    fn encode(&self, enc: Encoder) -> Encoder {
        enc
    }
}

impl BitcoinDecode for Verack {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        Ok((Self, dec))
    }
}
