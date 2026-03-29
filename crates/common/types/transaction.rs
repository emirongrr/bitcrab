//! Bitcoin transaction types.
//!
//! # Bitcoin Core
//!
//! `CTxIn`, `CTxOut`, `CTransaction` in `src/primitives/transaction.h`.
//!
//! Key differences from Bitcoin Core:
//!
//! | Field          | Bitcoin Core        | Bitcrab               |
//! |----------------|---------------------|-----------------------|
//! | output value   | `int64_t` (CAmount) | `Amount` (non-negative)|
//! | scripts        | `CScript`           | `ScriptBuf`           |
//! | mutability     | `CMutableTransaction` + `CTransaction` | one struct |
//! | serialization  | `SERIALIZE_METHODS` macro | explicit functions (later) |

use super::{
    amount::Amount,
    hash::Txid,
    script::ScriptBuf,
};

/// Reference to a specific unspent output (UTXO).
///
/// Bitcoin Core: `COutPoint` in `src/primitives/transaction.h`
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OutPoint {
    /// The transaction that created this output.
    pub txid: Txid,
    /// Index within that transaction's output list.
    pub vout: u32,
}

impl OutPoint {
    /// The sentinel coinbase outpoint (txid=0, vout=0xFFFFFFFF).
    ///
    /// Every coinbase transaction uses this as its single input's prevout.
    ///
    /// Bitcoin Core: `COutPoint()` default constructor.
    pub const COINBASE: Self = Self {
        txid: Txid::ZERO,
        vout: u32::MAX,
    };

    /// True if this is the coinbase sentinel.
    pub fn is_coinbase(&self) -> bool {
        self.txid == Txid::ZERO && self.vout == u32::MAX
    }
}

/// A transaction input.
///
/// Bitcoin Core: `CTxIn` in `src/primitives/transaction.h`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxIn {
    /// The output being spent.
    ///
    /// Bitcoin Core: `COutPoint prevout`
    pub previous_output: OutPoint,

    /// Unlocking script (empty for native segwit inputs).
    ///
    /// For P2PKH: contains <sig> <pubkey>.
    /// For P2SH: contains <data...> <redeemScript>.
    /// For P2WPKH / P2WSH / P2TR: must be empty — authorization is in `witness`.
    ///
    /// Bitcoin Core: `CScript scriptSig`
    pub script_sig: ScriptBuf,

    /// Sequence number.
    ///
    /// Dual-purpose (a design flaw):
    /// 1. Relative timelock (BIP-68) when version >= 2 and bit 31 clear.
    /// 2. Opt-in RBF signal (BIP-125) when < 0xFFFFFFFE.
    ///
    /// Bitcoin Core: `uint32_t nSequence`
    pub sequence: u32,

    /// Segregated witness stack.
    ///
    /// Empty for legacy (pre-SegWit) inputs.
    /// Excluded from txid computation — included in wtxid.
    ///
    /// Bitcoin Core: `CScriptWitness scriptWitness`
    pub witness: Vec<Vec<u8>>,
}

impl TxIn {
    /// Sequence value meaning "final" — no relative locktime, no RBF.
    ///
    /// Bitcoin Core: `CTxIn::SEQUENCE_FINAL = 0xffffffff`
    pub const SEQUENCE_FINAL: u32 = 0xFFFF_FFFF;

    /// Opt-in RBF threshold — sequence values below this signal replaceability.
    ///
    /// Bitcoin Core: signalled by `nSequence < MAX_BIP125_RBF_SEQUENCE`
    /// in `src/policy/rbf.h`
    pub const SEQUENCE_RBF_THRESHOLD: u32 = 0xFFFF_FFFE;

    /// True if this input signals opt-in Replace-By-Fee (BIP-125).
    pub fn signals_rbf(&self) -> bool {
        self.sequence < Self::SEQUENCE_RBF_THRESHOLD
    }

    /// True if relative locktime (BIP-68) is enabled for this input.
    ///
    /// BIP-68 is enabled when:
    /// - Transaction version >= 2
    /// - Bit 31 of sequence is clear
    pub fn has_relative_locktime(&self) -> bool {
        self.sequence & (1 << 31) == 0
    }
}

/// A transaction output — creates a new UTXO.
///
/// Bitcoin Core: `CTxOut` in `src/primitives/transaction.h`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    /// Value in satoshis.
    ///
    /// Bitcoin Core: `CAmount nValue` (int64_t — can be negative until checked).
    /// Bitcrab: `Amount` — negative is structurally impossible.
    pub value: Amount,

    /// Locking script — defines conditions to spend this output.
    ///
    /// Bitcoin Core: `CScript scriptPubKey`
    pub script_pubkey: ScriptBuf,
}

/// A complete Bitcoin transaction.
///
/// Bitcoin Core: `CTransaction` in `src/primitives/transaction.h`
///
/// Bitcoin Core has two types: `CTransaction` (immutable) and
/// `CMutableTransaction` (mutable). We use one struct.
/// Rust's borrow checker provides immutability when needed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    /// 1 = original. 2 = BIP-68 relative timelocks.
    ///
    /// Bitcoin Core: `int32_t nVersion`
    pub version: i32,

    /// Inputs — each spends a previous UTXO.
    ///
    /// Bitcoin Core: `std::vector<CTxIn> vin`
    pub input: Vec<TxIn>,

    /// Outputs — each creates a new UTXO.
    ///
    /// Bitcoin Core: `std::vector<CTxOut> vout`
    pub output: Vec<TxOut>,

    /// Locktime — earliest block/time this tx can be mined.
    ///
    /// 0: always final.
    /// 1–499_999_999: block height.
    /// 500_000_000+: Unix timestamp.
    ///
    /// Bitcoin Core: `uint32_t nLockTime`
    pub lock_time: u32,
}

impl Transaction {
    /// True if this is a coinbase transaction.
    ///
    /// Bitcoin Core: `CTransaction::IsCoinBase()` in `src/primitives/transaction.h`
    pub fn is_coinbase(&self) -> bool {
        self.input.len() == 1 && self.input[0].previous_output.is_coinbase()
    }

    /// True if any input has witness data.
    ///
    /// Bitcoin Core: `CTransaction::HasWitness()` in `src/primitives/transaction.h`
    pub fn is_segwit(&self) -> bool {
        self.input.iter().any(|i| !i.witness.is_empty())
    }

    /// Sum of all output values.
    ///
    /// Returns `None` if sum exceeds `MAX_MONEY`.
    ///
    /// Bitcoin Core: accumulates `nValueOut` in `CheckTransaction()`
    /// in `src/consensus/tx_check.cpp`
    pub fn output_value(&self) -> Option<Amount> {
        self.output
            .iter()
            .try_fold(Amount::ZERO, |acc, out| acc.checked_add(out.value))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::constants::COIN;

    #[test]
    fn coinbase_outpoint() {
        assert!(OutPoint::COINBASE.is_coinbase());
        assert!(!OutPoint { txid: Txid::from_bytes([1u8; 32]), vout: 0 }.is_coinbase());
    }

    #[test]
    fn rbf_signalling() {
        let mut inp = TxIn {
            previous_output: OutPoint::COINBASE,
            script_sig: ScriptBuf::new(),
            sequence: TxIn::SEQUENCE_FINAL,
            witness: vec![],
        };
        assert!(!inp.signals_rbf());

        inp.sequence = 0xFFFF_FFFE;
        assert!(!inp.signals_rbf()); // exactly at threshold, not below

        inp.sequence = 0xFFFF_FFFD;
        assert!(inp.signals_rbf());
    }

    #[test]
    fn output_value_sum() {
        let tx = Transaction {
            version: 1,
            input: vec![],
            output: vec![
                TxOut { value: Amount::from_sat(COIN).unwrap(), script_pubkey: ScriptBuf::new() },
                TxOut { value: Amount::from_sat(COIN).unwrap(), script_pubkey: ScriptBuf::new() },
            ],
            lock_time: 0,
        };
        assert_eq!(tx.output_value().unwrap().to_sat(), 2 * COIN);
    }

    #[test]
    fn segwit_detection() {
        let witness_inp = TxIn {
            previous_output: OutPoint::COINBASE,
            script_sig: ScriptBuf::new(),
            sequence: TxIn::SEQUENCE_FINAL,
            witness: vec![vec![0x01, 0x02]],
        };
        let tx = Transaction {
            version: 2,
            input: vec![witness_inp],
            output: vec![],
            lock_time: 0,
        };
        assert!(tx.is_segwit());
    }
}