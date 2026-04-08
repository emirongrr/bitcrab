//! Block message — response to GetData with InvType::Block.

use super::BitcoinMessage;
use crate::p2p::message::Command;
pub use bitcrab_common::types::block::Block;
use bitcrab_common::wire::{error::DecodeError, Decoder, Encoder, BitcoinEncode, BitcoinDecode};

impl BitcoinMessage for Block {
    const COMMAND: Command = Command::Block;

    fn encode(&self) -> Vec<u8> {
        let enc = Encoder::new();
        <Block as BitcoinEncode>::encode(self, enc).finish()
    }

    fn decode(payload: &[u8]) -> Result<Self, DecodeError> {
        let (block, _) = <Block as BitcoinDecode>::decode(Decoder::new(payload))?;
        Ok(block)
    }
}
