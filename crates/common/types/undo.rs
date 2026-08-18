//! Block Undo Data.
//!
//! Stores the state of UTXOs spent by a block, allowing the state to be reversed.

use super::block::Block;
use super::coin::Coin;
use super::transaction::OutPoint;
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

    /// Pair each spent coin with the outpoint it came from.
    ///
    /// `spent_coins` carries no outpoints — it is a flat list in consumption
    /// order — so the pairing is positional: walk the block's non-coinbase
    /// inputs in exactly the order `ConnectBlock` walked them when it built
    /// this record. Bitcoin Core does the same with `CBlockUndo::vtxundo`.
    ///
    /// That couples this function to `ConnectBlock`'s iteration order, and a
    /// silent desync would restore coins to the wrong outpoints — corruption
    /// that surfaces much later, in an unrelated block. The length check is the
    /// guard: a mismatch returns `None` rather than a plausible-looking answer.
    ///
    /// Bitcoin Core: the pairing loop in `DisconnectBlock`.
    pub fn pair_with_spends(&self, block: &Block) -> Option<Vec<(OutPoint, Coin)>> {
        // Coinbase inputs spend nothing, so ConnectBlock skips transaction 0.
        let outpoints: Vec<OutPoint> = block
            .transactions
            .iter()
            .skip(1)
            .flat_map(|tx| tx.inputs.iter().map(|input| input.previous_output.clone()))
            .collect();

        if outpoints.len() != self.spent_coins.len() {
            return None;
        }

        Some(
            outpoints
                .into_iter()
                .zip(self.spent_coins.iter().cloned())
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::amount::Amount;
    use crate::types::block::{Block, BlockHeader, BlockHeight};
    use crate::types::hash::{BlockHash, Hash256, Txid};
    use crate::types::script::ScriptBuf;
    use crate::types::transaction::{Transaction, TxIn, TxOut};

    fn tx(txid_seed: u8, input_count: usize, is_coinbase: bool) -> Transaction {
        Transaction {
            version: 2,
            inputs: (0..input_count)
                .map(|i| TxIn {
                    previous_output: OutPoint {
                        txid: if is_coinbase {
                            Txid::ZERO
                        } else {
                            Txid::from_bytes([txid_seed; 32])
                        },
                        vout: if is_coinbase { u32::MAX } else { i as u32 },
                    },
                    script_sig: ScriptBuf::from_bytes(vec![0x51, 0x51]),
                    sequence: 0xffff_ffff,
                    witness: Vec::new(),
                })
                .collect(),
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000).unwrap(),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
            lock_time: 0,
        }
    }

    fn block_with(txs: Vec<Transaction>) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                prev_hash: BlockHash::ZERO,
                merkle_root: Hash256::ZERO,
                time: 0,
                bits: 0x1d00_ffff,
                nonce: 0,
            },
            transactions: txs,
        }
    }

    fn coin(seed: u8) -> Coin {
        Coin::new(
            TxOut {
                value: Amount::from_sat(seed as u64 * 100).unwrap(),
                script_pubkey: ScriptBuf::from_bytes(vec![seed]),
            },
            BlockHeight(1),
            false,
        )
    }

    #[test]
    fn pairs_coins_with_inputs_in_consumption_order() {
        // Coinbase, then two transactions spending 2 and 1 inputs.
        let block = block_with(vec![tx(0, 1, true), tx(0xaa, 2, false), tx(0xbb, 1, false)]);

        let mut undo = BlockUndo::new();
        undo.push(coin(1));
        undo.push(coin(2));
        undo.push(coin(3));

        let paired = undo.pair_with_spends(&block).expect("counts match");
        assert_eq!(paired.len(), 3);

        // The coinbase must not appear.
        assert_eq!(paired[0].0.txid, Txid::from_bytes([0xaa; 32]));
        assert_eq!(paired[0].0.vout, 0);
        assert_eq!(paired[1].0.txid, Txid::from_bytes([0xaa; 32]));
        assert_eq!(paired[1].0.vout, 1);
        assert_eq!(paired[2].0.txid, Txid::from_bytes([0xbb; 32]));

        // Order is preserved, so coin N belongs to input N.
        assert_eq!(paired[0].1, coin(1));
        assert_eq!(paired[2].1, coin(3));
    }

    #[test]
    fn a_count_mismatch_is_refused_rather_than_guessed() {
        // This is the guard against ConnectBlock changing its iteration order:
        // a wrong pairing would restore coins to the wrong outpoints.
        let block = block_with(vec![tx(0, 1, true), tx(0xaa, 2, false)]);

        let mut too_few = BlockUndo::new();
        too_few.push(coin(1));
        assert_eq!(too_few.pair_with_spends(&block), None);

        let mut too_many = BlockUndo::new();
        for i in 0..3 {
            too_many.push(coin(i));
        }
        assert_eq!(too_many.pair_with_spends(&block), None);
    }

    #[test]
    fn a_block_with_only_a_coinbase_pairs_to_nothing() {
        let block = block_with(vec![tx(0, 1, true)]);
        assert_eq!(BlockUndo::new().pair_with_spends(&block), Some(Vec::new()));
    }

    #[test]
    fn undo_round_trips_through_the_wire_encoding() {
        // get_undo decodes what store_undo encoded; prove the pair survives.
        use crate::wire::encode::serialize;

        let mut undo = BlockUndo::new();
        undo.push(coin(7));
        undo.push(coin(9));

        let bytes = serialize(&undo);
        let (decoded, dec) = BlockUndo::decode(Decoder::new(&bytes)).unwrap();
        assert!(dec.is_done());
        assert_eq!(decoded, undo);
    }
}
