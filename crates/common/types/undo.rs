//! Block Undo Data.
//!
//! Stores the state of UTXOs spent by a block, allowing the state to be reversed.

use super::coin::Coin;
use crate::wire::{
    decode::{BitcoinDecode, Decoder},
    encode::{BitcoinEncode, Encoder, VarList},
    error::DecodeError,
};

/// Reversal state for a block's effects on the UTXO set.
///
/// Contains all coins spent by the block's transactions, allowing us to
/// restore them to the UTXO set if the block is disconnected (reorg).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockUndo {
    /// Coins spent by the transactions in the block (in order of consumption).
    pub spent_coins: Vec<Coin>,
}

impl BitcoinEncode for BlockUndo {
    fn encode(&self, enc: Encoder) -> Encoder {
        enc.encode_field(&VarList(&self.spent_coins))
    }
}

impl BitcoinDecode for BlockUndo {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        let (spent_coins, dec) = dec.read_var_list::<Coin>("BlockUndo")?;
        Ok((Self { spent_coins }, dec))
    }
}

impl BlockUndo {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, coin: Coin) {
        self.spent_coins.push(coin);
    }
}
