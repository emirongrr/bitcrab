use crate::p2p::{message::Command, wire::{DecodeError, Decoder, Encoder}};
use super::BitcoinMessage;

#[derive(Debug, Clone)]
pub struct Ping { pub nonce: u64 }

#[derive(Debug, Clone)]
pub struct Pong { pub nonce: u64 }

impl BitcoinMessage for Ping {
    const COMMAND: Command = Command::Ping;

    fn encode(&self) -> Vec<u8> {
        Encoder::new().write_u64_le(self.nonce).finish()
    }

    fn decode(p: &[u8]) -> Result<Self, DecodeError> {
        let (nonce, dec) = Decoder::new(p).read_u64_le("nonce")?;
        dec.finish()?;
        Ok(Self { nonce })
    }
}

impl BitcoinMessage for Pong {
    const COMMAND: Command = Command::Pong;

    fn encode(&self) -> Vec<u8> {
        Encoder::new().write_u64_le(self.nonce).finish()
    }

    fn decode(p: &[u8]) -> Result<Self, DecodeError> {
        let (nonce, dec) = Decoder::new(p).read_u64_le("nonce")?;
        dec.finish()?;
        Ok(Self { nonce })
    }
}