//! Ping and Pong messages — keepalive with nonce echo.
//!
//! Bitcoin Core: NetMsgType::PING / PONG in src/protocol.h
//! Both carry a single u64 nonce. Pong echoes the ping nonce.

use bitcrab_common::wire::{Decoder, Encoder, error::DecodeError};
use crate::p2p::message::Command;
use super::BitcoinMessage;

#[derive(Debug, Clone)]
pub struct Ping { pub nonce: u64 }

#[derive(Debug, Clone)]
pub struct Pong { pub nonce: u64 }

impl BitcoinMessage for Ping {
    const COMMAND: Command = Command::Ping;

    fn encode(&self) -> Vec<u8> {
        Encoder::new().encode_field(&self.nonce).finish()
    }

    fn decode(payload: &[u8]) -> Result<Self, DecodeError> {
        let (nonce, dec) = Decoder::new(payload).decode_field("nonce")?;
        dec.finish("ping")?;
        Ok(Self { nonce })
    }
}

impl BitcoinMessage for Pong {
    const COMMAND: Command = Command::Pong;

    fn encode(&self) -> Vec<u8> {
        Encoder::new().encode_field(&self.nonce).finish()
    }

    fn decode(payload: &[u8]) -> Result<Self, DecodeError> {
        let (nonce, dec) = Decoder::new(payload).decode_field("nonce")?;
        dec.finish("pong")?;
        Ok(Self { nonce })
    }
}