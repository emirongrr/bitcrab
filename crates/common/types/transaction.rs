//! Bitcoin transaction types.
//!
//! # Bitcoin Core
//!
//! `CTxIn`, `CTxOut`, `CTransaction` in `src/primitives/transaction.h`.

use super::{amount::Amount, hash::Txid, script::ScriptBuf};
use crate::wire::{
    decode::{BitcoinDecode, Decoder},
    encode::{BitcoinEncode, Encoder, VarList},
    error::DecodeError,
};

/// Reference to a specific unspent output (UTXO).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OutPoint {
    pub txid: Txid,
    pub vout: u32,
}

impl OutPoint {
    pub const COINBASE: Self = Self {
        txid: Txid::ZERO,
        vout: u32::MAX,
    };

    pub fn is_coinbase(&self) -> bool {
        self.txid == Txid::ZERO && self.vout == u32::MAX
    }
}

impl BitcoinEncode for OutPoint {
    fn encode(&self, enc: Encoder) -> Encoder {
        enc.encode_field(self.txid.as_bytes())
           .encode_field(&self.vout)
    }
}

impl BitcoinDecode for OutPoint {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        let (txid_bytes, dec) = dec.decode_field::<[u8; 32]>("OutPoint::txid")?;
        let (vout, dec) = dec.decode_field::<u32>("OutPoint::vout")?;
        Ok((Self {
            txid: Txid::from_bytes(txid_bytes),
            vout,
        }, dec))
    }
}

/// A transaction input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxIn {
    pub previous_output: OutPoint,
    pub script_sig: ScriptBuf,
    pub sequence: u32,
    /// SegWit witness stack (Vec of push-data elements).
    pub witness: Vec<Vec<u8>>,
}

impl TxIn {
    pub const SEQUENCE_FINAL: u32 = 0xFFFF_FFFF;
    pub fn is_final(&self) -> bool {
        self.sequence == Self::SEQUENCE_FINAL
    }
}

impl BitcoinEncode for TxIn {
    fn encode(&self, enc: Encoder) -> Encoder {
        enc.encode_field(&self.previous_output)
           .encode_field(&self.script_sig)
           .encode_field(&self.sequence)
    }
}

impl BitcoinDecode for TxIn {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        let (prev, dec) = dec.decode_field::<OutPoint>("TxIn::previous_output")?;
        let (sig, dec) = dec.decode_field::<ScriptBuf>("TxIn::script_sig")?;
        let (seq, dec) = dec.decode_field::<u32>("TxIn::sequence")?;
        Ok((Self {
            previous_output: prev,
            script_sig: sig,
            sequence: seq,
            witness: Vec::new(),
        }, dec))
    }
}

/// A transaction output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    pub value: Amount,
    pub script_pubkey: ScriptBuf,
}

impl BitcoinEncode for TxOut {
    fn encode(&self, enc: Encoder) -> Encoder {
        enc.encode_field(&self.value)
           .encode_field(&self.script_pubkey)
    }
}

impl BitcoinDecode for TxOut {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        let (val, dec) = dec.decode_field::<Amount>("TxOut::value")?;
        let (script, dec) = dec.decode_field::<ScriptBuf>("TxOut::script_pubkey")?;
        Ok((Self {
            value: val,
            script_pubkey: script,
        }, dec))
    }
}

/// A Bitcoin transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub version: u32,
    /// Inputs — each spends a UTXO.
    pub inputs: Vec<TxIn>,
    /// Outputs — each creates a new UTXO.
    pub outputs: Vec<TxOut>,
    /// Locktime — earliest block/time this tx can be mined.
    pub lock_time: u32,
}

impl Transaction {
    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].previous_output.is_coinbase()
    }

    pub fn is_segwit(&self) -> bool {
        self.inputs.iter().any(|i| !i.witness.is_empty())
    }

    pub fn output_value(&self) -> Option<Amount> {
        self.outputs
            .iter()
            .try_fold(Amount::ZERO, |acc, out| acc.checked_add(out.value))
    }

    /// Calculate the transaction hash (TXID).
    pub fn txid(&self) -> super::hash::Txid {
        let mut enc = Encoder::new();
        enc = enc.encode_field(&self.version)
                 .encode_field(&VarList(&self.inputs))
                 .encode_field(&VarList(&self.outputs))
                 .encode_field(&self.lock_time);
        super::hash::Txid::hash(&enc.finish())
    }

    /// Calculate the signature hash for a specific input.
    ///
    /// Bitcoin Core: `SignatureHash()` in `src/script/interpreter.cpp`.
    /// Currently implements standard SIGHASH_ALL for legacy transactions.
    pub fn signature_hash(
        &self,
        input_index: usize,
        script_pubkey: &super::script::ScriptBuf,
        sighash_type: u32,
    ) -> [u8; 32] {
        if input_index >= self.inputs.len() {
            // Bitcoin Core returns 1.0.0...0 hash for out-of-bounds input index
            let mut oob = [0u8; 32];
            oob[0] = 1;
            return oob;
        }

        // 1. Create a simplified copy of the transaction
        let mut tx_copy = self.clone();

        // 2. Clear all input scripts
        for input in &mut tx_copy.inputs {
            input.script_sig = super::script::ScriptBuf::new();
        }

        // 3. Set the scriptSig of the input being signed to the scriptPubKey
        // Note: In real Bitcoin, this also involves removing OP_CODESEPARATORs.
        tx_copy.inputs[input_index].script_sig = script_pubkey.clone();

        // 4. Handle SIGHASH_NONE / SIGHASH_SINGLE (TODO)
        // For SIGHASH_ALL (1), we do nothing else.

        // 5. Serialize and append sighash type
        let mut enc = Encoder::new();
        enc = enc.encode_field(&tx_copy.version)
                 .encode_field(&VarList(&tx_copy.inputs))
                 .encode_field(&VarList(&tx_copy.outputs))
                 .encode_field(&tx_copy.lock_time)
                 .encode_field(&sighash_type);

        // 6. Double-SHA256
        super::hash::hash256(&enc.finish())
    }

    /// Calculate the witness transaction hash (WTXID).
    pub fn wtxid(&self) -> super::hash::Txid {
        if !self.is_segwit() {
            return self.txid();
        }
        super::hash::Txid::hash(&self.encode(Encoder::new()).finish())
    }
}

impl BitcoinEncode for Transaction {
    fn encode(&self, enc: Encoder) -> Encoder {
        if self.is_segwit() {
            let mut enc = enc.encode_field(&self.version)
                             .encode_field(&0u8) // Marker
                             .encode_field(&1u8); // Flag
            
            enc = enc.encode_field(&VarList(&self.inputs))
                     .encode_field(&VarList(&self.outputs));
            
            for input in &self.inputs {
                enc = enc.encode_field(&VarList(&input.witness));
            }
            
            enc.encode_field(&self.lock_time)
        } else {
            enc.encode_field(&self.version)
               .encode_field(&VarList(&self.inputs))
               .encode_field(&VarList(&self.outputs))
               .encode_field(&self.lock_time)
        }
    }
}

impl BitcoinDecode for Transaction {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        let (version, dec) = dec.decode_field::<u32>("Transaction::version")?;
        
        let (marker, _peek_dec) = dec.decode_field::<u8>("Transaction::marker")?;
        
        if marker == 0 {
            let (_, dec) = dec.decode_field::<u8>("Transaction::marker")?;
            let (flag, dec) = dec.decode_field::<u8>("Transaction::flag")?;
            if flag != 1 {
                return Err(DecodeError::Custom("invalid SegWit flag".into()));
            }
            
            let (mut inputs, dec) = dec.read_var_list::<TxIn>("Transaction::inputs")?;
            let (outputs, dec) = dec.read_var_list::<TxOut>("Transaction::outputs")?;
            
            let mut dec = dec;
            for input in &mut inputs {
                let (witness, next_dec) = dec.read_var_list::<Vec<u8>>("Transaction::witness")?;
                input.witness = witness;
                dec = next_dec;
            }
            
            let (lock_time, dec) = dec.decode_field::<u32>("Transaction::lock_time")?;
            
            Ok((Self {
                version,
                inputs,
                outputs,
                lock_time,
            }, dec))
        } else {
            let (inputs, dec) = dec.read_var_list::<TxIn>("Transaction::inputs")?;
            let (outputs, dec) = dec.read_var_list::<TxOut>("Transaction::outputs")?;
            let (lock_time, dec) = dec.decode_field::<u32>("Transaction::lock_time")?;
            
            Ok((Self {
                version,
                inputs,
                outputs,
                lock_time,
            }, dec))
        }
    }
}
