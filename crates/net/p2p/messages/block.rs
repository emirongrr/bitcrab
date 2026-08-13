//! Block message — response to GetData with InvType::Block.

use super::BitcoinMessage;
use crate::p2p::message::Command;
pub use bitcrab_common::types::block::Block;
use bitcrab_common::wire::{decode_exact, error::DecodeError, BitcoinEncode, Encoder};

impl BitcoinMessage for Block {
    const COMMAND: Command = Command::Block;

    fn encode(&self) -> Vec<u8> {
        let enc = Encoder::new();
        <Block as BitcoinEncode>::encode(self, enc).finish()
    }

    fn decode(payload: &[u8]) -> Result<Self, DecodeError> {
        decode_exact::<Block>(payload, "block")
    }
}
