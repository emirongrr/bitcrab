//! Verack — acknowledges a version message. Zero-byte payload.
//!
//! Bitcoin Core: NetMsgType::VERACK in src/protocol.h

use super::BitcoinMessage;
use crate::p2p::message::Command;
use bitcrab_common::wire::error::DecodeError;

#[derive(Debug, Clone)]
pub struct Verack;

impl BitcoinMessage for Verack {
    const COMMAND: Command = Command::Verack;

    fn encode(&self) -> Vec<u8> {
        vec![]
    }

    fn decode(_payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self)
    }
}
