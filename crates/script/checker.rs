//! Signature checking against a transaction.
//!
//! Bitcoin Core: `BaseSignatureChecker` / `TransactionSignatureChecker` in
//! `src/script/interpreter.h`.
//!
//! The interpreter never touches a transaction directly; it asks a checker.
//! That is what lets the same `EvalScript` serve real validation, the signet
//! block-solution check, and unit tests with a stub checker.

use bitcrab_common::types::transaction::{Transaction, TxOut};
use secp256k1::{
    ecdsa::Signature, schnorr, Message, PublicKey, Secp256k1, Verification, XOnlyPublicKey,
};

use crate::error::{ScriptError, ScriptResult};
use crate::num::ScriptNum;
use crate::sighash::{
    legacy_signature_hash, taproot_signature_hash, witness_v0_signature_hash, Bip143Cache,
    TaprootCache, SIGHASH_DEFAULT,
};
use crate::taproot::ScriptExecutionData;

/// Which signature hashing scheme applies.
///
/// Bitcoin Core: `SigVersion`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigVersion {
    /// Pre-segwit scripts (scriptSig / redeemScript).
    Base,
    /// Witness v0 (P2WPKH, P2WSH) — BIP 143.
    WitnessV0,
    /// Taproot key-path spend — BIP 341, `ext_flag = 0`.
    Taproot,
    /// Taproot script-path spend — BIP 342, `ext_flag = 1`.
    Tapscript,
}

/// Threshold separating block heights from unix timestamps in nLockTime.
///
/// Bitcoin Core: `LOCKTIME_THRESHOLD` in `src/script/script.h`.
pub const LOCKTIME_THRESHOLD: i64 = 500_000_000;

/// Bitcoin Core: `CTxIn::SEQUENCE_FINAL`.
pub const SEQUENCE_FINAL: u32 = 0xffff_ffff;
/// Bitcoin Core: `CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG`.
pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: i64 = 1 << 31;
/// Bitcoin Core: `CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG`.
pub const SEQUENCE_LOCKTIME_TYPE_FLAG: i64 = 1 << 22;
/// Bitcoin Core: `CTxIn::SEQUENCE_LOCKTIME_MASK`.
pub const SEQUENCE_LOCKTIME_MASK: i64 = 0x0000_ffff;

/// All midstates a transaction's signature hashes need.
///
/// Bitcoin Core: `PrecomputedTransactionData`. Computing these once per
/// transaction rather than once per input is what keeps segwit and taproot
/// validation linear.
#[derive(Debug, Clone)]
pub struct PrecomputedTransactionData {
    pub bip143: Bip143Cache,
    pub taproot: TaprootCache,
}

impl PrecomputedTransactionData {
    pub fn new(tx: &Transaction, spent_outputs: &[TxOut]) -> Self {
        Self {
            bip143: Bip143Cache::new(tx),
            taproot: TaprootCache::new(tx, spent_outputs),
        }
    }
}

/// What the interpreter needs from its surrounding transaction.
pub trait SignatureChecker {
    /// Verify an ECDSA signature over the appropriate sighash.
    ///
    /// `sig` includes its trailing hash-type byte. Returns `false` — never an
    /// error — for a failed check; encoding errors are the caller's job.
    fn check_ecdsa_signature(
        &self,
        sig: &[u8],
        pubkey: &[u8],
        script_code: &[u8],
        sig_version: SigVersion,
    ) -> bool;

    /// Verify a BIP 340 schnorr signature.
    ///
    /// Returns `Ok(())` only on a valid signature. Taproot has no "pushes
    /// false" outcome for a non-empty signature — a failed check aborts the
    /// script, which is what makes `NULLFAIL` unnecessary there. Returning
    /// `Result<(), _>` rather than `Result<bool, _>` keeps a caller from
    /// discarding the verdict with `?`.
    ///
    /// Bitcoin Core: `GenericTransactionSignatureChecker::CheckSchnorrSignature`.
    fn check_schnorr_signature(
        &self,
        _sig: &[u8],
        _pubkey: &[u8],
        _sig_version: SigVersion,
        _exec_data: &ScriptExecutionData,
    ) -> ScriptResult<()> {
        Err(ScriptError::SchnorrSig)
    }

    /// Bitcoin Core: `CheckLockTime()`.
    fn check_lock_time(&self, _lock_time: ScriptNum) -> bool {
        false
    }

    /// Bitcoin Core: `CheckSequence()`.
    fn check_sequence(&self, _sequence: ScriptNum) -> bool {
        false
    }
}

/// A checker that fails every signature.
///
/// Bitcoin Core: `BaseSignatureChecker`. Useful for evaluating scripts that
/// must not depend on signatures.
pub struct NullSignatureChecker;

impl SignatureChecker for NullSignatureChecker {
    fn check_ecdsa_signature(&self, _: &[u8], _: &[u8], _: &[u8], _: SigVersion) -> bool {
        false
    }
}

/// Checks signatures against a real transaction input.
///
/// Bitcoin Core: `TransactionSignatureChecker`.
pub struct TransactionSignatureChecker<'a, C: Verification> {
    tx: &'a Transaction,
    input_index: usize,
    spent_outputs: &'a [TxOut],
    cache: PrecomputedTransactionData,
    secp: &'a Secp256k1<C>,
}

impl<'a, C: Verification> TransactionSignatureChecker<'a, C> {
    /// `spent_outputs` must be the outputs this transaction spends, in input
    /// order. Taproot commits to all of them, so a partial list is not enough.
    pub fn new(
        tx: &'a Transaction,
        input_index: usize,
        spent_outputs: &'a [TxOut],
        secp: &'a Secp256k1<C>,
    ) -> Self {
        Self {
            tx,
            input_index,
            spent_outputs,
            cache: PrecomputedTransactionData::new(tx, spent_outputs),
            secp,
        }
    }

    /// Reuse midstates already computed for this transaction.
    pub fn with_cache(mut self, cache: PrecomputedTransactionData) -> Self {
        self.cache = cache;
        self
    }

    fn amount(&self) -> i64 {
        self.spent_outputs
            .get(self.input_index)
            .map(|output| output.value.to_sat() as i64)
            .unwrap_or(0)
    }
}

impl<C: Verification> SignatureChecker for TransactionSignatureChecker<'_, C> {
    fn check_ecdsa_signature(
        &self,
        sig: &[u8],
        pubkey: &[u8],
        script_code: &[u8],
        sig_version: SigVersion,
    ) -> bool {
        // Split the trailing hash-type byte off the DER body.
        let Some((&hash_type, sig_der)) = sig.split_last() else {
            return false;
        };
        if sig_der.is_empty() {
            return false;
        }

        let Ok(pubkey) = PublicKey::from_slice(pubkey) else {
            return false;
        };
        // Core uses a lenient DER parse here and enforces strictness through
        // the separate encoding checks, so a "lax" parse is correct.
        let Ok(signature) = Signature::from_der_lax(sig_der) else {
            return false;
        };

        let digest = match sig_version {
            SigVersion::Base => {
                legacy_signature_hash(self.tx, self.input_index, script_code, hash_type as u32)
            }
            SigVersion::WitnessV0 => witness_v0_signature_hash(
                self.tx,
                self.input_index,
                script_code,
                self.amount(),
                hash_type as u32,
                &self.cache.bip143,
            ),
            // Taproot never uses ECDSA.
            SigVersion::Taproot | SigVersion::Tapscript => return false,
        };

        self.secp
            .verify_ecdsa(&Message::from_digest(digest), &signature, &pubkey)
            .is_ok()
    }

    fn check_schnorr_signature(
        &self,
        sig: &[u8],
        pubkey: &[u8],
        sig_version: SigVersion,
        exec_data: &ScriptExecutionData,
    ) -> ScriptResult<()> {
        // BIP 341: 64 bytes means SIGHASH_DEFAULT; 65 carries an explicit hash
        // type, which must not be SIGHASH_DEFAULT (that would be a second
        // encoding of the same thing).
        let (signature_bytes, hash_type) = match sig.len() {
            64 => (sig, SIGHASH_DEFAULT),
            65 => {
                let hash_type = sig[64];
                if hash_type == SIGHASH_DEFAULT {
                    return Err(ScriptError::SchnorrSigHashType);
                }
                (&sig[..64], hash_type)
            }
            _ => return Err(ScriptError::SchnorrSigSize),
        };

        let ext_flag = match sig_version {
            SigVersion::Taproot => 0,
            SigVersion::Tapscript => 1,
            _ => return Err(ScriptError::SchnorrSig),
        };

        let Ok(pubkey) = XOnlyPublicKey::from_slice(pubkey) else {
            return Err(ScriptError::SchnorrSigPubkey);
        };
        let Ok(signature) = schnorr::Signature::from_slice(signature_bytes) else {
            return Err(ScriptError::SchnorrSig);
        };

        let Some(digest) = taproot_signature_hash(
            self.tx,
            self.input_index,
            self.spent_outputs,
            hash_type,
            ext_flag,
            exec_data,
            &self.cache.taproot,
        ) else {
            // The only way this fails is SIGHASH_SINGLE with no matching
            // output, which taproot treats as an invalid hash type.
            return Err(ScriptError::SchnorrSigHashType);
        };

        self.secp
            .verify_schnorr(&signature, &Message::from_digest(digest), &pubkey)
            .map_err(|_| ScriptError::SchnorrSig)
    }

    /// Bitcoin Core: `TransactionSignatureChecker::CheckLockTime()`.
    fn check_lock_time(&self, lock_time: ScriptNum) -> bool {
        let stack_value = lock_time.as_i64();
        let tx_lock_time = self.tx.lock_time as i64;

        // Both must be the same kind: block height or timestamp. Comparing
        // across the two would be meaningless.
        let same_kind = (tx_lock_time < LOCKTIME_THRESHOLD && stack_value < LOCKTIME_THRESHOLD)
            || (tx_lock_time >= LOCKTIME_THRESHOLD && stack_value >= LOCKTIME_THRESHOLD);
        if !same_kind {
            return false;
        }

        if stack_value > tx_lock_time {
            return false;
        }

        // A final sequence means nLockTime is not actually enforced, so the
        // whole check would be a no-op and must be rejected.
        if self.tx.inputs[self.input_index].sequence == SEQUENCE_FINAL {
            return false;
        }

        true
    }

    /// Bitcoin Core: `TransactionSignatureChecker::CheckSequence()`.
    fn check_sequence(&self, sequence: ScriptNum) -> bool {
        let stack_value = sequence.as_i64();
        let tx_sequence = self.tx.inputs[self.input_index].sequence as i64;

        // Relative locktime only applies from tx version 2 onward.
        if self.tx.version < 2 {
            return false;
        }
        if tx_sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            return false;
        }

        let tx_masked = tx_sequence & (SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK);
        let stack_masked = stack_value & (SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK);

        // Again, block-based and time-based locks are not comparable.
        let same_kind = (tx_masked < SEQUENCE_LOCKTIME_TYPE_FLAG
            && stack_masked < SEQUENCE_LOCKTIME_TYPE_FLAG)
            || (tx_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG
                && stack_masked >= SEQUENCE_LOCKTIME_TYPE_FLAG);
        if !same_kind {
            return false;
        }

        stack_masked <= tx_masked
    }
}
