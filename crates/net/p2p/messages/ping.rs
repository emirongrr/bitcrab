//! Ping and Pong messages — keepalive with nonce echo.
//!
//! Bitcoin Core: NetMsgType::PING / PONG in src/protocol.h
//! Both carry a single u64 nonce. Pong echoes the ping nonce.

use super::BitcoinMessage;
use crate::p2p::message::Command;
use bitcrab_common::wire::{
    decode_exact, error::DecodeError, BitcoinDecode, BitcoinEncode, Decoder, Encoder,
};

#[derive(Debug, Clone)]
pub struct Ping {
    pub nonce: u64,
}

#[derive(Debug, Clone)]
pub struct Pong {
    pub nonce: u64,
}

impl BitcoinMessage for Ping {
    const COMMAND: Command = Command::Ping;

    fn encode(&self) -> Vec<u8> {
        Encoder::new().encode_field(self).finish()
    }

    fn decode(payload: &[u8]) -> Result<Self, DecodeError> {
        decode_exact::<Self>(payload, "ping")
    }
}

impl BitcoinMessage for Pong {
    const COMMAND: Command = Command::Pong;

    fn encode(&self) -> Vec<u8> {
        Encoder::new().encode_field(self).finish()
    }

    fn decode(payload: &[u8]) -> Result<Self, DecodeError> {
        decode_exact::<Self>(payload, "pong")
    }
}

impl BitcoinEncode for Ping {
    fn encode(&self, enc: Encoder) -> Encoder {
        enc.encode_field(&self.nonce)
    }
}

impl BitcoinDecode for Ping {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        let (nonce, dec) = dec.decode_field("nonce")?;
        Ok((Self { nonce }, dec))
    }
}

impl BitcoinEncode for Pong {
    fn encode(&self, enc: Encoder) -> Encoder {
        enc.encode_field(&self.nonce)
    }
}

impl BitcoinDecode for Pong {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        let (nonce, dec) = dec.decode_field("nonce")?;
        Ok((Self { nonce }, dec))
    }
}
