//! GetData message — Requests one or more data objects from another node.

use super::inv::InvVector;
use super::BitcoinMessage;
use crate::p2p::message::Command;
use bitcrab_common::wire::{encode::VarInt, error::DecodeError, Decoder, Encoder};

#[derive(Debug, Clone)]
pub struct GetData {
    pub inventory: Vec<InvVector>,
}

impl BitcoinMessage for GetData {
    const COMMAND: Command = Command::GetData;

    fn encode(&self) -> Vec<u8> {
        let mut enc = Encoder::new().encode_field(&VarInt(self.inventory.len() as u64));
        for item in &self.inventory {
            enc = enc
                .encode_field(&(item.inv_type as u32))
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
                inv_type: super::inv::InvType::from_u32(typ),
                hash,
            });
            dec = d;
        }
        Ok(Self { inventory })
    }
}
