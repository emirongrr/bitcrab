//! Inv message — Announces knowledge of objects (blocks, txs).

use super::BitcoinMessage;
use crate::p2p::message::Command;
use bitcrab_common::wire::{
    decode_exact, encode::VarInt, error::DecodeError, BitcoinDecode, BitcoinEncode, Decoder,
    Encoder,
};

const MAX_INV_ENTRIES: usize = 50_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvType {
    Error = 0,
    Tx = 1,
    Block = 2,
    FilteredBlock = 3,
    CmpctBlock = 4,
    Wtx = 5,
    WitnessTx = 1 | 0x40000000,
    WitnessBlock = 2 | 0x40000000,
    FilteredWitnessBlock = 3 | 0x40000000,
}

// const MSG_WITNESS_FLAG: u32 = 0x40000000;

impl InvType {
    pub fn from_u32(val: u32) -> Self {
        match val {
            1 => InvType::Tx,
            2 => InvType::Block,
            3 => InvType::FilteredBlock,
            4 => InvType::CmpctBlock,
            5 => InvType::Wtx,
            1073741825 => InvType::WitnessTx,    // 1 | 0x40000000
            1073741826 => InvType::WitnessBlock, // 2 | 0x40000000
            1073741827 => InvType::FilteredWitnessBlock, // 3 | 0x40000000
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
        Encoder::new().encode_field(self).finish()
    }

    fn decode(payload: &[u8]) -> Result<Self, DecodeError> {
        decode_exact::<Self>(payload, "inv")
    }
}

impl BitcoinEncode for InvVector {
    fn encode(&self, enc: Encoder) -> Encoder {
        enc.encode_field(&(self.inv_type as u32))
            .encode_field(&self.hash)
    }
}

impl BitcoinDecode for InvVector {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        let (typ, dec) = dec.decode_field::<u32>("inv_type")?;
        let (hash, dec) = dec.decode_field::<[u8; 32]>("hash")?;
        Ok((
            Self {
                inv_type: InvType::from_u32(typ),
                hash,
            },
            dec,
        ))
    }
}

impl BitcoinEncode for Inv {
    fn encode(&self, enc: Encoder) -> Encoder {
        self.inventory.iter().fold(
            enc.encode_field(&VarInt(self.inventory.len() as u64)),
            |enc, item| enc.encode_field(item),
        )
    }
}

impl BitcoinDecode for Inv {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        let (count, mut dec) = dec.read_varint("inv_count")?;
        if count as usize > MAX_INV_ENTRIES {
            return Err(DecodeError::AllocationTooLarge {
                field: "inv_count",
                len: count,
                limit: MAX_INV_ENTRIES,
            });
        }
        let mut inventory = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let (item, next_dec) = dec.decode_field::<InvVector>("inv_vector")?;
            inventory.push(item);
            dec = next_dec;
        }
        Ok((Self { inventory }, dec))
    }
}
