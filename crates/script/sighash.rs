//! Transaction signature hashes.
//!
//! Bitcoin Core: `SignatureHash()` in `src/script/interpreter.cpp`.
//!
//! Two schemes are implemented:
//!
//! * **Legacy** — the original algorithm. Serialises a mutated copy of the
//!   transaction. Carries the `SIGHASH_SINGLE` bug (an out-of-range input
//!   returns the constant hash `0x0000...0001` instead of failing) which is
//!   consensus and must be reproduced exactly.
//! * **BIP 143** — used by witness v0. Precomputes three midstate hashes so
//!   signing is linear rather than quadratic in the number of inputs, and
//!   commits to the spent amount.

use bitcrab_common::types::hash::{hash256, sha256};
use bitcrab_common::types::transaction::{Transaction, TxOut};
use bitcrab_common::wire::encode::{Encoder, VarBytes, VarInt};

use crate::sig::{SIGHASH_ALL, SIGHASH_ANYONECANPAY, SIGHASH_NONE, SIGHASH_SINGLE};
use crate::taproot::{tagged_hash, ScriptExecutionData};

/// The value legacy hashing returns for an out-of-range `SIGHASH_SINGLE`.
///
/// Bitcoin Core returns `uint256::ONE` here rather than failing. It is a bug
/// from 2010 that is now permanently part of consensus.
pub const SIGHASH_SINGLE_BUG: [u8; 32] = {
    let mut bug = [0u8; 32];
    bug[0] = 1;
    bug
};

/// Legacy (pre-segwit) signature hash.
///
/// Bitcoin Core: `SignatureHash()` with `sigversion == SigVersion::BASE`.
///
/// `script_code` must already have had `FindAndDelete` applied by the caller.
pub fn legacy_signature_hash(
    tx: &Transaction,
    input_index: usize,
    script_code: &[u8],
    hash_type: u32,
) -> [u8; 32] {
    let base_type = (hash_type & 0x1f) as u8;
    let anyone_can_pay = hash_type as u8 & SIGHASH_ANYONECANPAY != 0;

    if input_index >= tx.inputs.len() {
        return SIGHASH_SINGLE_BUG;
    }
    // The SIGHASH_SINGLE bug: there is no output to pair with this input.
    if base_type == SIGHASH_SINGLE && input_index >= tx.outputs.len() {
        return SIGHASH_SINGLE_BUG;
    }

    let mut enc = Encoder::new().encode_field(&tx.version);

    // Inputs. With ANYONECANPAY only the signed input is committed to.
    let signed_inputs: Vec<usize> = if anyone_can_pay {
        vec![input_index]
    } else {
        (0..tx.inputs.len()).collect()
    };

    enc = enc.encode_field(&VarInt(signed_inputs.len() as u64));
    for &i in &signed_inputs {
        let input = &tx.inputs[i];
        enc = enc.encode_field(&input.previous_output);

        // Only the input being signed carries a scriptCode; the others are
        // blanked so signatures do not commit to each other.
        if i == input_index {
            enc = enc.encode_field(&VarBytes(script_code));
        } else {
            enc = enc.encode_field(&VarBytes(&[]));
        }

        // SIGHASH_NONE / SIGHASH_SINGLE blank the sequences of other inputs so
        // they stay free to change.
        let sequence =
            if i != input_index && (base_type == SIGHASH_NONE || base_type == SIGHASH_SINGLE) {
                0
            } else {
                input.sequence
            };
        enc = enc.encode_field(&sequence);
    }

    // Outputs.
    match base_type {
        SIGHASH_NONE => {
            enc = enc.encode_field(&VarInt(0));
        }
        SIGHASH_SINGLE => {
            // Commit only to the output at the same index; everything before it
            // is serialised as a "null" output.
            enc = enc.encode_field(&VarInt((input_index + 1) as u64));
            for i in 0..=input_index {
                if i < input_index {
                    // Bitcoin Core serialises a default CTxOut here: nValue = -1.
                    enc = enc.encode_field(&(-1i64));
                    enc = enc.encode_field(&VarBytes(&[]));
                } else {
                    enc = enc.encode_field(&(tx.outputs[i].value.to_sat() as i64));
                    enc = enc.encode_field(&VarBytes(tx.outputs[i].script_pubkey.as_bytes()));
                }
            }
        }
        _ => {
            enc = enc.encode_field(&VarInt(tx.outputs.len() as u64));
            for output in &tx.outputs {
                enc = enc.encode_field(&(output.value.to_sat() as i64));
                enc = enc.encode_field(&VarBytes(output.script_pubkey.as_bytes()));
            }
        }
    }

    enc = enc.encode_field(&tx.lock_time);
    enc = enc.encode_field(&hash_type);

    hash256(&enc.finish())
}

/// The three midstate hashes BIP 143 reuses across inputs.
///
/// Bitcoin Core: `PrecomputedTransactionData`.
#[derive(Debug, Clone, Default)]
pub struct Bip143Cache {
    pub hash_prevouts: [u8; 32],
    pub hash_sequence: [u8; 32],
    pub hash_outputs: [u8; 32],
}

impl Bip143Cache {
    pub fn new(tx: &Transaction) -> Self {
        let mut prevouts = Encoder::new();
        for input in &tx.inputs {
            prevouts = prevouts.encode_field(&input.previous_output);
        }

        let mut sequences = Encoder::new();
        for input in &tx.inputs {
            sequences = sequences.encode_field(&input.sequence);
        }

        let mut outputs = Encoder::new();
        for output in &tx.outputs {
            outputs = outputs.encode_field(&(output.value.to_sat() as i64));
            outputs = outputs.encode_field(&VarBytes(output.script_pubkey.as_bytes()));
        }

        Self {
            hash_prevouts: hash256(&prevouts.finish()),
            hash_sequence: hash256(&sequences.finish()),
            hash_outputs: hash256(&outputs.finish()),
        }
    }
}

/// BIP 143 signature hash, used by witness v0 inputs.
///
/// Bitcoin Core: `SignatureHash()` with `sigversion == SigVersion::WITNESS_V0`.
pub fn witness_v0_signature_hash(
    tx: &Transaction,
    input_index: usize,
    script_code: &[u8],
    amount_sat: i64,
    hash_type: u32,
    cache: &Bip143Cache,
) -> [u8; 32] {
    let base_type = (hash_type & 0x1f) as u8;
    let anyone_can_pay = hash_type as u8 & SIGHASH_ANYONECANPAY != 0;

    let zero = [0u8; 32];

    let hash_prevouts = if anyone_can_pay {
        zero
    } else {
        cache.hash_prevouts
    };

    let hash_sequence =
        if anyone_can_pay || base_type == SIGHASH_SINGLE || base_type == SIGHASH_NONE {
            zero
        } else {
            cache.hash_sequence
        };

    let hash_outputs = if base_type != SIGHASH_SINGLE && base_type != SIGHASH_NONE {
        cache.hash_outputs
    } else if base_type == SIGHASH_SINGLE && input_index < tx.outputs.len() {
        let output = &tx.outputs[input_index];
        let enc = Encoder::new()
            .encode_field(&(output.value.to_sat() as i64))
            .encode_field(&VarBytes(output.script_pubkey.as_bytes()));
        hash256(&enc.finish())
    } else {
        // BIP 143 specifies zero here — unlike legacy, this is not the
        // SIGHASH_SINGLE bug value.
        zero
    };

    let input = &tx.inputs[input_index];

    let enc = Encoder::new()
        .encode_field(&tx.version)
        .encode_field(&hash_prevouts)
        .encode_field(&hash_sequence)
        .encode_field(&input.previous_output)
        .encode_field(&VarBytes(script_code))
        .encode_field(&amount_sat)
        .encode_field(&input.sequence)
        .encode_field(&hash_outputs)
        .encode_field(&tx.lock_time)
        .encode_field(&hash_type);

    hash256(&enc.finish())
}

// ---------------------------------------------------------------------------
// BIP 341 — taproot
// ---------------------------------------------------------------------------

/// `SIGHASH_DEFAULT` — taproot's implicit "sign everything".
///
/// Distinct from `SIGHASH_ALL`: it is encoded by *omitting* the hash-type byte
/// entirely, giving a 64-byte signature instead of 65.
pub const SIGHASH_DEFAULT: u8 = 0x00;

/// Midstates BIP 341 reuses across the inputs of one transaction.
///
/// Bitcoin Core: the taproot half of `PrecomputedTransactionData`.
///
/// Unlike BIP 143, taproot commits to *every* spent output's amount and
/// scriptPubKey, so building this requires the full prevout set.
#[derive(Debug, Clone, Default)]
pub struct TaprootCache {
    pub sha_prevouts: [u8; 32],
    pub sha_amounts: [u8; 32],
    pub sha_scriptpubkeys: [u8; 32],
    pub sha_sequences: [u8; 32],
    pub sha_outputs: [u8; 32],
}

impl TaprootCache {
    /// `spent_outputs` must be the outputs this transaction spends, in input order.
    pub fn new(tx: &Transaction, spent_outputs: &[TxOut]) -> Self {
        let mut prevouts = Encoder::new();
        for input in &tx.inputs {
            prevouts = prevouts.encode_field(&input.previous_output);
        }

        let mut amounts = Encoder::new();
        for output in spent_outputs {
            amounts = amounts.encode_field(&(output.value.to_sat() as i64));
        }

        let mut script_pubkeys = Encoder::new();
        for output in spent_outputs {
            script_pubkeys =
                script_pubkeys.encode_field(&VarBytes(output.script_pubkey.as_bytes()));
        }

        let mut sequences = Encoder::new();
        for input in &tx.inputs {
            sequences = sequences.encode_field(&input.sequence);
        }

        let mut outputs = Encoder::new();
        for output in &tx.outputs {
            outputs = outputs.encode_field(&(output.value.to_sat() as i64));
            outputs = outputs.encode_field(&VarBytes(output.script_pubkey.as_bytes()));
        }

        // Taproot uses single SHA-256 for these, not the usual double hash.
        Self {
            sha_prevouts: sha256(&prevouts.finish()),
            sha_amounts: sha256(&amounts.finish()),
            sha_scriptpubkeys: sha256(&script_pubkeys.finish()),
            sha_sequences: sha256(&sequences.finish()),
            sha_outputs: sha256(&outputs.finish()),
        }
    }
}

/// BIP 341 signature hash.
///
/// Bitcoin Core: `SignatureHashSchnorr()` in `src/script/interpreter.cpp`.
///
/// `ext_flag` is 0 for a key-path spend and 1 for tapscript; the tapscript
/// extension appends the leaf hash, key version and codeseparator position.
/// Returns `None` for the one invalid combination — `SIGHASH_SINGLE` with no
/// output at this index — which taproot rejects outright rather than papering
/// over the way legacy hashing does.
#[allow(clippy::too_many_arguments)]
pub fn taproot_signature_hash(
    tx: &Transaction,
    input_index: usize,
    spent_outputs: &[TxOut],
    hash_type: u8,
    ext_flag: u8,
    exec_data: &ScriptExecutionData,
    cache: &TaprootCache,
) -> Option<[u8; 32]> {
    let output_type = if hash_type == SIGHASH_DEFAULT {
        SIGHASH_ALL
    } else {
        hash_type & 3
    };
    let input_type = hash_type & SIGHASH_ANYONECANPAY;

    if input_index >= tx.inputs.len() || spent_outputs.len() != tx.inputs.len() {
        return None;
    }
    if output_type == SIGHASH_SINGLE && input_index >= tx.outputs.len() {
        return None;
    }

    let mut msg = Vec::with_capacity(210);

    // Epoch — hashed in but not part of SigMsg proper.
    msg.push(0x00);

    msg.push(hash_type);
    msg.extend_from_slice(&tx.version.to_le_bytes());
    msg.extend_from_slice(&tx.lock_time.to_le_bytes());

    if input_type != SIGHASH_ANYONECANPAY {
        msg.extend_from_slice(&cache.sha_prevouts);
        msg.extend_from_slice(&cache.sha_amounts);
        msg.extend_from_slice(&cache.sha_scriptpubkeys);
        msg.extend_from_slice(&cache.sha_sequences);
    }
    if output_type == SIGHASH_ALL {
        msg.extend_from_slice(&cache.sha_outputs);
    }

    let annex_present = exec_data.annex_hash.is_some();
    let spend_type = (ext_flag << 1) | u8::from(annex_present);
    msg.push(spend_type);

    if input_type == SIGHASH_ANYONECANPAY {
        // Commit to this input in full, since the others are not covered.
        let input = &tx.inputs[input_index];
        let spent = &spent_outputs[input_index];
        msg.extend_from_slice(&Encoder::new().encode_field(&input.previous_output).finish());
        msg.extend_from_slice(&(spent.value.to_sat() as i64).to_le_bytes());
        msg.extend_from_slice(
            &Encoder::new()
                .encode_field(&VarBytes(spent.script_pubkey.as_bytes()))
                .finish(),
        );
        msg.extend_from_slice(&input.sequence.to_le_bytes());
    } else {
        msg.extend_from_slice(&(input_index as u32).to_le_bytes());
    }

    if let Some(annex_hash) = exec_data.annex_hash {
        msg.extend_from_slice(&annex_hash);
    }

    if output_type == SIGHASH_SINGLE {
        let output = &tx.outputs[input_index];
        let enc = Encoder::new()
            .encode_field(&(output.value.to_sat() as i64))
            .encode_field(&VarBytes(output.script_pubkey.as_bytes()));
        msg.extend_from_slice(&sha256(&enc.finish()));
    }

    if ext_flag == 1 {
        // Tapscript extension.
        msg.extend_from_slice(&exec_data.tapleaf_hash?);
        msg.push(0x00); // key version
        msg.extend_from_slice(&exec_data.codeseparator_pos.to_le_bytes());
    }

    Some(tagged_hash("TapSighash", &msg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcrab_common::types::amount::Amount;
    use bitcrab_common::types::hash::Txid;
    use bitcrab_common::types::script::ScriptBuf;
    use bitcrab_common::types::transaction::{OutPoint, TxIn};

    fn tx_with(inputs: usize, outputs: usize) -> Transaction {
        Transaction {
            version: 2,
            inputs: (0..inputs)
                .map(|i| TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_bytes([i as u8; 32]),
                        vout: i as u32,
                    },
                    script_sig: ScriptBuf::from_bytes(vec![0x51]),
                    sequence: 0xffff_fffe,
                    witness: Vec::new(),
                })
                .collect(),
            outputs: (0..outputs)
                .map(|i| TxOut {
                    value: Amount::from_sat(1_000 * (i as u64 + 1)).unwrap(),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x6a, i as u8]),
                })
                .collect(),
            lock_time: 0,
        }
    }

    #[test]
    fn out_of_range_input_returns_the_sighash_single_bug_value() {
        let tx = tx_with(1, 1);
        assert_eq!(
            legacy_signature_hash(&tx, 5, &[0x51], SIGHASH_ALL as u32),
            SIGHASH_SINGLE_BUG
        );
    }

    #[test]
    fn sighash_single_without_a_matching_output_hits_the_bug() {
        // Two inputs, one output: signing input 1 with SIGHASH_SINGLE has no
        // output to pair with. Core returns 0x01..00 rather than failing.
        let tx = tx_with(2, 1);
        assert_eq!(
            legacy_signature_hash(&tx, 1, &[0x51], SIGHASH_SINGLE as u32),
            SIGHASH_SINGLE_BUG
        );
        // Input 0 does have a matching output, so it hashes normally.
        assert_ne!(
            legacy_signature_hash(&tx, 0, &[0x51], SIGHASH_SINGLE as u32),
            SIGHASH_SINGLE_BUG
        );
    }

    #[test]
    fn hash_type_changes_the_digest() {
        let tx = tx_with(2, 2);
        let all = legacy_signature_hash(&tx, 0, &[0x51], SIGHASH_ALL as u32);
        let none = legacy_signature_hash(&tx, 0, &[0x51], SIGHASH_NONE as u32);
        let single = legacy_signature_hash(&tx, 0, &[0x51], SIGHASH_SINGLE as u32);
        let all_acp =
            legacy_signature_hash(&tx, 0, &[0x51], (SIGHASH_ALL | SIGHASH_ANYONECANPAY) as u32);

        let digests = [all, none, single, all_acp];
        for i in 0..digests.len() {
            for j in i + 1..digests.len() {
                assert_ne!(
                    digests[i], digests[j],
                    "hash types {} and {} collided",
                    i, j
                );
            }
        }
    }

    #[test]
    fn script_code_is_committed_to() {
        let tx = tx_with(1, 1);
        let a = legacy_signature_hash(&tx, 0, &[0x51], SIGHASH_ALL as u32);
        let b = legacy_signature_hash(&tx, 0, &[0x52], SIGHASH_ALL as u32);
        assert_ne!(a, b);
    }

    #[test]
    fn sighash_none_ignores_output_changes() {
        let mut tx = tx_with(2, 2);
        let before = legacy_signature_hash(&tx, 0, &[0x51], SIGHASH_NONE as u32);
        tx.outputs[1].value = Amount::from_sat(999_999).unwrap();
        let after = legacy_signature_hash(&tx, 0, &[0x51], SIGHASH_NONE as u32);
        assert_eq!(before, after, "SIGHASH_NONE must not commit to outputs");
    }

    #[test]
    fn sighash_all_does_commit_to_output_changes() {
        let mut tx = tx_with(2, 2);
        let before = legacy_signature_hash(&tx, 0, &[0x51], SIGHASH_ALL as u32);
        tx.outputs[1].value = Amount::from_sat(999_999).unwrap();
        let after = legacy_signature_hash(&tx, 0, &[0x51], SIGHASH_ALL as u32);
        assert_ne!(before, after);
    }

    #[test]
    fn anyonecanpay_ignores_other_inputs() {
        let mut tx = tx_with(2, 2);
        let hash_type = (SIGHASH_ALL | SIGHASH_ANYONECANPAY) as u32;
        let before = legacy_signature_hash(&tx, 0, &[0x51], hash_type);
        tx.inputs[1].previous_output.vout = 77;
        let after = legacy_signature_hash(&tx, 0, &[0x51], hash_type);
        assert_eq!(
            before, after,
            "ANYONECANPAY must not commit to other inputs"
        );
    }

    #[test]
    fn bip143_commits_to_the_spent_amount() {
        let tx = tx_with(1, 1);
        let cache = Bip143Cache::new(&tx);
        let a = witness_v0_signature_hash(&tx, 0, &[0x51], 50_000, SIGHASH_ALL as u32, &cache);
        let b = witness_v0_signature_hash(&tx, 0, &[0x51], 50_001, SIGHASH_ALL as u32, &cache);
        assert_ne!(a, b, "BIP143 must commit to the input amount");
    }

    #[test]
    fn bip143_differs_from_legacy_for_the_same_inputs() {
        let tx = tx_with(1, 1);
        let cache = Bip143Cache::new(&tx);
        let legacy = legacy_signature_hash(&tx, 0, &[0x51], SIGHASH_ALL as u32);
        let segwit = witness_v0_signature_hash(&tx, 0, &[0x51], 1_000, SIGHASH_ALL as u32, &cache);
        assert_ne!(legacy, segwit);
    }

    #[test]
    fn bip143_single_out_of_range_uses_zero_not_the_legacy_bug() {
        let tx = tx_with(2, 1);
        let cache = Bip143Cache::new(&tx);
        let digest =
            witness_v0_signature_hash(&tx, 1, &[0x51], 1_000, SIGHASH_SINGLE as u32, &cache);
        // Unlike legacy, BIP143 produces a normal digest over a zeroed
        // hashOutputs rather than the 0x01..00 sentinel.
        assert_ne!(digest, SIGHASH_SINGLE_BUG);
    }
}
