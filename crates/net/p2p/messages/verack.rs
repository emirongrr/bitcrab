//! Verack — acknowledges a version message. Zero-byte payload.
//!
//! Bitcoin Core: NetMsgType::VERACK in src/protocol.h

use bitcrab_common::wire::error::DecodeError;
use crate::p2p::message::Command;
use super::BitcoinMessage;

#[derive(Debug, Clone)]
pub struct Verack;

impl BitcoinMessage for Verack {
    const COMMAND: Command = Command::Verack;

    fn encode(&self) -> Vec<u8> { vec![] }

    fn decode(_payload: &[u8]) -> Result<Self, DecodeError> { Ok(Self) }
}