//! Inv message — Announces knowledge of objects (blocks, txs).

use super::BitcoinMessage;
use crate::p2p::message::Command;
use bitcrab_common::{
    wire::{encode::VarInt, error::DecodeError, Decoder, Encoder},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvType {
    Error = 0,
    Tx = 1,
    Block = 2,
    FilteredBlock = 3,
    CmpctBlock = 4,
}

impl InvType {
    pub fn from_u32(val: u32) -> Self {
        match val {
            1 => InvType::Tx,
            2 => InvType::Block,
            3 => InvType::FilteredBlock,
            4 => InvType::CmpctBlock,
            _ => InvType::Error,
        }
    }
}

#[derive(Debug, Clone)]
pub struct InvVector {
    pub inv_type: InvType,
    pub hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct Inv {
    pub inventory: Vec<InvVector>,
}

impl BitcoinMessage for Inv {
    const COMMAND: Command = Command::Inv;

    fn encode(&self) -> Vec<u8> {
        let mut enc = Encoder::new().encode_field(&VarInt(self.inventory.len() as u64));
        for item in &self.inventory {
            enc = enc.encode_field(&(item.inv_type as u32))
                     .encode_field(&item.hash);
        }
        enc.finish()
    }

    fn decode(payload: &[u8]) -> Result<Self, DecodeError> {
        let dec = Decoder::new(payload);
        let (count, mut dec) = dec.read_varint("inv_count")?;
        let mut inventory = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let (typ, d) = dec.decode_field::<u32>("inv_type")?;
            let (hash, d) = d.decode_field::<[u8; 32]>("hash")?;
            inventory.push(InvVector {
                inv_type: InvType::from_u32(typ),
                hash,
            });
            dec = d;
        }
        Ok(Self { inventory })
    }
}
