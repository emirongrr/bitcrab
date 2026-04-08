//! UTXO (Unspent Transaction Output) representation.
//!
//! Matches Bitcoin Core's `CCoin` class in `src/coins.h`.
//! A coin consists of an output and metadata about its origin.

use crate::types::{block::BlockHeight, transaction::TxOut};
use crate::wire::{
    decode::{BitcoinDecode, Decoder},
    encode::{BitcoinEncode, Encoder},
    error::DecodeError,
};

/// A single unspent transaction output record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coin {
    /// The value and script of the output.
    pub output: TxOut,
    /// The height of the block where this coin was created.
    pub height: BlockHeight,
    /// True if the coin was created by a coinbase transaction.
    pub is_coinbase: bool,
}

impl Coin {
    pub fn new(output: TxOut, height: BlockHeight, is_coinbase: bool) -> Self {
        Self {
            output,
            height,
            is_coinbase,
        }
    }
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

impl BitcoinEncode for Coin {
    fn encode(&self, enc: Encoder) -> Encoder {
        enc.encode_field(&self.height)
            .encode_field(&self.is_coinbase)
            .encode_field(&self.output)
    }
}

impl BitcoinDecode for Coin {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        let (height, dec) = BlockHeight::decode(dec)?;
        let (is_coinbase, dec) = bool::decode(dec)?;
        let (output, dec) = TxOut::decode(dec)?;
        Ok((Self { output, height, is_coinbase }, dec))
    }
}
