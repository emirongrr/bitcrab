//! GetData message — Requests one or more data objects from another node.

use super::inv::InvVector;
use super::BitcoinMessage;
use crate::p2p::message::Command;
use bitcrab_common::wire::{
    decode_exact, encode::VarInt, error::DecodeError, BitcoinDecode, BitcoinEncode, Decoder,
    Encoder,
};

const MAX_GETDATA_ENTRIES: usize = 50_000;

#[derive(Debug, Clone)]
pub struct GetData {
    pub inventory: Vec<InvVector>,
}

impl BitcoinMessage for GetData {
    const COMMAND: Command = Command::GetData;

    fn encode(&self) -> Vec<u8> {
        Encoder::new().encode_field(self).finish()
    }

    fn decode(payload: &[u8]) -> Result<Self, DecodeError> {
        decode_exact::<Self>(payload, "getdata")
    }
}

impl BitcoinEncode for GetData {
    fn encode(&self, enc: Encoder) -> Encoder {
        self.inventory.iter().fold(
            enc.encode_field(&VarInt(self.inventory.len() as u64)),
            |enc, item| enc.encode_field(item),
        )
    }
}

impl BitcoinDecode for GetData {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        let (count, mut dec) = dec.read_varint("inv_count")?;
        if count as usize > MAX_GETDATA_ENTRIES {
            return Err(DecodeError::AllocationTooLarge {
                field: "inv_count",
                len: count,
                limit: MAX_GETDATA_ENTRIES,
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
