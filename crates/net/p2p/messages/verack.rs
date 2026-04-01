use crate::p2p::{message::Command, wire::DecodeError};
use super::BitcoinMessage;

#[derive(Debug, Clone)]
pub struct Verack;

impl BitcoinMessage for Verack {
    const COMMAND: Command = Command::Verack;

    fn encode(&self) -> Vec<u8> { vec![] }

    fn decode(_payload: &[u8]) -> Result<Self, DecodeError> { Ok(Self) }
}