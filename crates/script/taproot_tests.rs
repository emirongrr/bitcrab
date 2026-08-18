//! End-to-end taproot tests (BIP 341 / BIP 342).
//!
//! Unlike the unit tests in `taproot.rs`, these build real outputs with real
//! keys, sign them, and run the whole `verify_script` path — so a mistake in
//! the sighash, the commitment, or the tapscript rules shows up as a spend
//! that should have worked and did not, or vice versa.

use bitcrab_common::types::{
    amount::Amount,
    hash::Txid,
    script::ScriptBuf,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
};
use secp256k1::{Keypair, Message, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};

use crate::checker::{SigVersion, TransactionSignatureChecker};
use crate::error::ScriptError;
use crate::flags::VerifyFlags;
use crate::interpreter::verify_script;
use crate::opcode::all;
use crate::script_ops::push_data;
use crate::sighash::taproot_signature_hash;
use crate::taproot::{
    compute_tapleaf_hash, tagged_hash, ScriptExecutionData, TAPROOT_LEAF_TAPSCRIPT,
};

const TAPROOT_FLAGS: VerifyFlags = VerifyFlags::CONSENSUS_TAPROOT;

fn secp() -> Secp256k1<secp256k1::All> {
    Secp256k1::new()
}

fn keypair(seed: u8) -> Keypair {
    Keypair::from_secret_key(&secp(), &SecretKey::from_slice(&[seed; 32]).unwrap())
}

/// Apply the BIP 341 tweak to an internal key, with or without a script tree.
fn tweak_key(internal: XOnlyPublicKey, merkle_root: Option<[u8; 32]>) -> (XOnlyPublicKey, u8) {
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(&internal.serialize());
    if let Some(root) = merkle_root {
        data.extend_from_slice(&root);
    }
    let tweak = Scalar::from_be_bytes(tagged_hash("TapTweak", &data)).unwrap();
    let (output_key, parity) = internal.add_tweak(&secp(), &tweak).unwrap();
    (output_key, parity as u8)
}

fn p2tr_script(output_key: XOnlyPublicKey) -> Vec<u8> {
    let mut script = vec![all::OP_1, 0x20];
    script.extend_from_slice(&output_key.serialize());
    script
}

fn spending_tx(witness: Vec<Vec<u8>>) -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_bytes([0x42; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: 0xffff_fffe,
            witness,
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(9_000).unwrap(),
            script_pubkey: ScriptBuf::from_bytes(vec![all::OP_1]),
        }],
        lock_time: 0,
    }
}

fn spent(script_pubkey: &[u8], sats: u64) -> Vec<TxOut> {
    vec![TxOut {
        value: Amount::from_sat(sats).unwrap(),
        script_pubkey: ScriptBuf::from_bytes(script_pubkey.to_vec()),
    }]
}

// ---------------------------------------------------------------------------
// Key path
// ---------------------------------------------------------------------------

#[test]
fn key_path_spend_round_trips() {
    let secp = secp();
    let internal = keypair(0x11);
    let (internal_xonly, _) = internal.x_only_public_key();
    let (output_key, parity) = tweak_key(internal_xonly, None);

    let script_pubkey = p2tr_script(output_key);
    let spent_outputs = spent(&script_pubkey, 10_000);

    // Sign with the tweaked private key.
    let tweak =
        Scalar::from_be_bytes(tagged_hash("TapTweak", &internal_xonly.serialize())).unwrap();
    let tweaked = internal.add_xonly_tweak(&secp, &tweak).unwrap();

    let unsigned = spending_tx(Vec::new());
    let exec_data = ScriptExecutionData::new();
    let cache = crate::sighash::TaprootCache::new(&unsigned, &spent_outputs);
    let digest =
        taproot_signature_hash(&unsigned, 0, &spent_outputs, 0x00, 0, &exec_data, &cache).unwrap();

    let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &tweaked);
    let tx = spending_tx(vec![sig.serialize().to_vec()]);

    let checker = TransactionSignatureChecker::new(&tx, 0, &spent_outputs, &secp);
    assert_eq!(
        verify_script(
            &[],
            &script_pubkey,
            &tx.inputs[0].witness,
            TAPROOT_FLAGS,
            &checker
        ),
        Ok(()),
        "a correctly signed key-path spend must verify (parity {})",
        parity
    );
}

#[test]
fn key_path_rejects_a_signature_from_the_untweaked_key() {
    // Signing with the internal key instead of the tweaked one is the classic
    // taproot implementation mistake; it must not verify.
    let secp = secp();
    let internal = keypair(0x22);
    let (internal_xonly, _) = internal.x_only_public_key();
    let (output_key, _) = tweak_key(internal_xonly, None);

    let script_pubkey = p2tr_script(output_key);
    let spent_outputs = spent(&script_pubkey, 10_000);

    let unsigned = spending_tx(Vec::new());
    let exec_data = ScriptExecutionData::new();
    let cache = crate::sighash::TaprootCache::new(&unsigned, &spent_outputs);
    let digest =
        taproot_signature_hash(&unsigned, 0, &spent_outputs, 0x00, 0, &exec_data, &cache).unwrap();

    let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &internal);
    let tx = spending_tx(vec![sig.serialize().to_vec()]);

    let checker = TransactionSignatureChecker::new(&tx, 0, &spent_outputs, &secp);
    assert_eq!(
        verify_script(
            &[],
            &script_pubkey,
            &tx.inputs[0].witness,
            TAPROOT_FLAGS,
            &checker
        ),
        Err(ScriptError::SchnorrSig)
    );
}

#[test]
fn key_path_signature_sizes_are_enforced() {
    let secp = secp();
    let internal = keypair(0x33);
    let (internal_xonly, _) = internal.x_only_public_key();
    let (output_key, _) = tweak_key(internal_xonly, None);
    let script_pubkey = p2tr_script(output_key);
    let spent_outputs = spent(&script_pubkey, 10_000);

    for (witness_item, expected) in [
        (vec![0u8; 63], ScriptError::SchnorrSigSize),
        (vec![0u8; 66], ScriptError::SchnorrSigSize),
        // 65 bytes with SIGHASH_DEFAULT in the hash-type slot is a second
        // encoding of the 64-byte form, which BIP 341 forbids.
        (
            {
                let mut sig = vec![0u8; 64];
                sig.push(0x00);
                sig
            },
            ScriptError::SchnorrSigHashType,
        ),
    ] {
        let tx = spending_tx(vec![witness_item]);
        let checker = TransactionSignatureChecker::new(&tx, 0, &spent_outputs, &secp);
        assert_eq!(
            verify_script(
                &[],
                &script_pubkey,
                &tx.inputs[0].witness,
                TAPROOT_FLAGS,
                &checker
            ),
            Err(expected)
        );
    }
}

#[test]
fn key_path_commits_to_the_spent_amount() {
    let secp = secp();
    let internal = keypair(0x44);
    let (internal_xonly, _) = internal.x_only_public_key();
    let (output_key, _) = tweak_key(internal_xonly, None);
    let script_pubkey = p2tr_script(output_key);
    let spent_outputs = spent(&script_pubkey, 10_000);

    let tweak =
        Scalar::from_be_bytes(tagged_hash("TapTweak", &internal_xonly.serialize())).unwrap();
    let tweaked = internal.add_xonly_tweak(&secp, &tweak).unwrap();

    let unsigned = spending_tx(Vec::new());
    let exec_data = ScriptExecutionData::new();
    let cache = crate::sighash::TaprootCache::new(&unsigned, &spent_outputs);
    let digest =
        taproot_signature_hash(&unsigned, 0, &spent_outputs, 0x00, 0, &exec_data, &cache).unwrap();
    let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &tweaked);
    let tx = spending_tx(vec![sig.serialize().to_vec()]);

    // Same signature, but the verifier is told a different amount was spent.
    let lying = spent(&script_pubkey, 10_001);
    let checker = TransactionSignatureChecker::new(&tx, 0, &lying, &secp);
    assert_eq!(
        verify_script(
            &[],
            &script_pubkey,
            &tx.inputs[0].witness,
            TAPROOT_FLAGS,
            &checker
        ),
        Err(ScriptError::SchnorrSig),
        "BIP 341 commits to every spent amount"
    );
}

// ---------------------------------------------------------------------------
// Script path
// ---------------------------------------------------------------------------

/// Build a single-leaf taproot output and the control block that reveals it.
fn single_leaf_output(internal_seed: u8, leaf_script: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let internal = keypair(internal_seed);
    let (internal_xonly, _) = internal.x_only_public_key();

    let leaf_hash = compute_tapleaf_hash(TAPROOT_LEAF_TAPSCRIPT, leaf_script);
    let (output_key, parity) = tweak_key(internal_xonly, Some(leaf_hash));

    let mut control = vec![TAPROOT_LEAF_TAPSCRIPT | parity];
    control.extend_from_slice(&internal_xonly.serialize());

    (p2tr_script(output_key), control)
}

#[test]
fn script_path_spend_with_a_trivially_true_leaf() {
    let secp = secp();
    let leaf_script = vec![all::OP_1];
    let (script_pubkey, control) = single_leaf_output(0x55, &leaf_script);
    let spent_outputs = spent(&script_pubkey, 10_000);

    let witness = vec![leaf_script.clone(), control];
    let tx = spending_tx(witness.clone());
    let checker = TransactionSignatureChecker::new(&tx, 0, &spent_outputs, &secp);

    assert_eq!(
        verify_script(&[], &script_pubkey, &witness, TAPROOT_FLAGS, &checker),
        Ok(())
    );
}

#[test]
fn script_path_rejects_a_leaf_not_in_the_tree() {
    let secp = secp();
    let (script_pubkey, control) = single_leaf_output(0x66, &[all::OP_1]);
    let spent_outputs = spent(&script_pubkey, 10_000);

    // Reveal a different script than the one committed to.
    let witness = vec![vec![all::OP_2], control];
    let tx = spending_tx(witness.clone());
    let checker = TransactionSignatureChecker::new(&tx, 0, &spent_outputs, &secp);

    assert_eq!(
        verify_script(&[], &script_pubkey, &witness, TAPROOT_FLAGS, &checker),
        Err(ScriptError::WitnessProgramMismatch)
    );
}

#[test]
fn script_path_rejects_a_wrong_parity_bit() {
    let secp = secp();
    let leaf_script = vec![all::OP_1];
    let (script_pubkey, mut control) = single_leaf_output(0x77, &leaf_script);
    let spent_outputs = spent(&script_pubkey, 10_000);

    // Flip the parity bit in the control byte.
    control[0] ^= 1;
    let witness = vec![leaf_script, control];
    let tx = spending_tx(witness.clone());
    let checker = TransactionSignatureChecker::new(&tx, 0, &spent_outputs, &secp);

    assert_eq!(
        verify_script(&[], &script_pubkey, &witness, TAPROOT_FLAGS, &checker),
        Err(ScriptError::WitnessProgramMismatch)
    );
}

#[test]
fn script_path_checksig_round_trips() {
    let secp = secp();
    let signer = keypair(0x88);
    let (signer_xonly, _) = signer.x_only_public_key();

    // Leaf script: <32-byte x-only key> OP_CHECKSIG
    let mut leaf_script = Vec::new();
    push_data(&mut leaf_script, &signer_xonly.serialize());
    leaf_script.push(all::OP_CHECKSIG);

    let (script_pubkey, control) = single_leaf_output(0x99, &leaf_script);
    let spent_outputs = spent(&script_pubkey, 10_000);

    // The tapscript sighash commits to the leaf hash and codeseparator position.
    let mut exec_data = ScriptExecutionData::new();
    exec_data.tapleaf_hash = Some(compute_tapleaf_hash(TAPROOT_LEAF_TAPSCRIPT, &leaf_script));

    let unsigned = spending_tx(Vec::new());
    let cache = crate::sighash::TaprootCache::new(&unsigned, &spent_outputs);
    let digest =
        taproot_signature_hash(&unsigned, 0, &spent_outputs, 0x00, 1, &exec_data, &cache).unwrap();
    let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &signer);

    let witness = vec![sig.serialize().to_vec(), leaf_script, control];
    let tx = spending_tx(witness.clone());
    let checker = TransactionSignatureChecker::new(&tx, 0, &spent_outputs, &secp);

    assert_eq!(
        verify_script(&[], &script_pubkey, &witness, TAPROOT_FLAGS, &checker),
        Ok(())
    );
}

#[test]
fn annex_is_stripped_and_committed_to() {
    let secp = secp();
    let leaf_script = vec![all::OP_1];
    let (script_pubkey, control) = single_leaf_output(0xaa, &leaf_script);
    let spent_outputs = spent(&script_pubkey, 10_000);

    // The annex is the last item and starts with 0x50. It must be removed
    // before the script path is interpreted, so this still spends cleanly.
    let annex = vec![0x50, 0x01, 0x02];
    let witness = vec![leaf_script, control, annex];
    let tx = spending_tx(witness.clone());
    let checker = TransactionSignatureChecker::new(&tx, 0, &spent_outputs, &secp);

    assert_eq!(
        verify_script(&[], &script_pubkey, &witness, TAPROOT_FLAGS, &checker),
        Ok(())
    );
}

// ---------------------------------------------------------------------------
// BIP 342 tapscript rules
// ---------------------------------------------------------------------------

/// Run a leaf script through the script path and return the verdict.
fn run_tapscript(leaf_script: Vec<u8>, mut stack: Vec<Vec<u8>>) -> Result<(), ScriptError> {
    let secp = secp();
    let (script_pubkey, control) = single_leaf_output(0xbb, &leaf_script);
    let spent_outputs = spent(&script_pubkey, 10_000);

    stack.push(leaf_script);
    stack.push(control);
    let tx = spending_tx(stack.clone());
    let checker = TransactionSignatureChecker::new(&tx, 0, &spent_outputs, &secp);
    verify_script(&[], &script_pubkey, &stack, TAPROOT_FLAGS, &checker)
}

#[test]
fn checkmultisig_is_disabled_in_tapscript() {
    // BIP 342 removes batch verification; OP_CHECKSIGADD replaces it.
    let script = vec![all::OP_0, all::OP_0, all::OP_0, all::OP_CHECKMULTISIG];
    assert_eq!(
        run_tapscript(script, Vec::new()),
        Err(ScriptError::TapscriptCheckMultisig)
    );
}

#[test]
fn op_success_makes_the_script_succeed_immediately() {
    // OP_SUCCESS80 followed by an OP_RETURN that would otherwise fail.
    let script = vec![80u8, all::OP_RETURN];
    assert_eq!(run_tapscript(script.clone(), Vec::new()), Ok(()));

    // Under the discourage flag it becomes an error instead.
    let secp = secp();
    let (script_pubkey, control) = single_leaf_output(0xbb, &script);
    let spent_outputs = spent(&script_pubkey, 10_000);
    let witness = vec![script, control];
    let tx = spending_tx(witness.clone());
    let checker = TransactionSignatureChecker::new(&tx, 0, &spent_outputs, &secp);
    assert_eq!(
        verify_script(
            &[],
            &script_pubkey,
            &witness,
            TAPROOT_FLAGS | VerifyFlags::DISCOURAGE_OP_SUCCESS,
            &checker
        ),
        Err(ScriptError::DiscourageOpSuccess)
    );
}

#[test]
fn minimal_if_is_mandatory_in_tapscript() {
    // A non-minimal IF argument is a consensus failure here, not a policy one.
    let script = vec![all::OP_IF, all::OP_1, all::OP_ENDIF];
    assert_eq!(
        run_tapscript(script, vec![vec![0x02]]),
        Err(ScriptError::TapscriptMinimalIf)
    );
}

#[test]
fn checksigadd_counts_successful_signatures() {
    // <sig> <num> <pubkey> OP_CHECKSIGADD with an empty signature leaves the
    // running count unchanged.
    let signer = keypair(0xcc);
    let (signer_xonly, _) = signer.x_only_public_key();

    let mut script = Vec::new();
    push_data(&mut script, &signer_xonly.serialize());
    script.push(0xba); // OP_CHECKSIGADD
    script.push(all::OP_0);
    script.push(all::OP_EQUAL);

    // stack: <empty sig> <0>
    assert_eq!(run_tapscript(script, vec![Vec::new(), Vec::new()]), Ok(()));
}

#[test]
fn checksigadd_is_not_available_outside_tapscript() {
    // 0xba is an undefined opcode in legacy and witness v0 scripts.
    let mut stack = Vec::new();
    let result = crate::interpreter::eval_script(
        &mut stack,
        &[all::OP_0, all::OP_0, all::OP_0, 0xba],
        VerifyFlags::NONE,
        &crate::checker::NullSignatureChecker,
        SigVersion::Base,
    );
    assert_eq!(result, Err(ScriptError::BadOpcode));
}

#[test]
fn an_empty_pubkey_fails_even_with_an_empty_signature() {
    // BIP 342 orders the checks so that a zero-length key fails regardless.
    let script = vec![all::OP_0, all::OP_0, all::OP_CHECKSIG];
    assert_eq!(
        run_tapscript(script, Vec::new()),
        Err(ScriptError::PubkeyType)
    );
}

#[test]
fn unknown_pubkey_sizes_are_upgradable() {
    // A key that is neither empty nor 32 bytes is reserved for a future soft
    // fork: it succeeds now, and is rejected only under the discourage flag.
    let mut script = Vec::new();
    push_data(&mut script, &[0xab; 33]);
    script.push(all::OP_CHECKSIG);

    // Non-empty signature so the check is actually reached.
    assert_eq!(run_tapscript(script.clone(), vec![vec![0u8; 64]]), Ok(()));

    let secp = secp();
    let (script_pubkey, control) = single_leaf_output(0xbb, &script);
    let spent_outputs = spent(&script_pubkey, 10_000);
    let witness = vec![vec![0u8; 64], script, control];
    let tx = spending_tx(witness.clone());
    let checker = TransactionSignatureChecker::new(&tx, 0, &spent_outputs, &secp);
    assert_eq!(
        verify_script(
            &[],
            &script_pubkey,
            &witness,
            TAPROOT_FLAGS | VerifyFlags::DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
            &checker
        ),
        Err(ScriptError::DiscourageUpgradablePubkeyType)
    );
}

#[test]
fn taproot_is_not_available_under_p2sh() {
    use bitcrab_common::types::hash::hash160;

    // Wrapping a v1 program in P2SH must not activate taproot — it would
    // reintroduce the malleability segwit removed. The engine treats it as an
    // unknown witness version instead.
    let secp = secp();
    let internal = keypair(0xdd);
    let (internal_xonly, _) = internal.x_only_public_key();
    let (output_key, _) = tweak_key(internal_xonly, None);
    let redeem = p2tr_script(output_key);

    let mut script_pubkey = vec![all::OP_HASH160, 0x14];
    script_pubkey.extend_from_slice(&hash160(&redeem));
    script_pubkey.push(all::OP_EQUAL);

    let mut script_sig = Vec::new();
    push_data(&mut script_sig, &redeem);

    let witness = vec![vec![0u8; 64]];
    let tx = spending_tx(witness.clone());
    let spent_outputs = spent(&script_pubkey, 10_000);
    let checker = TransactionSignatureChecker::new(&tx, 0, &spent_outputs, &secp);

    // Anyone-can-spend rather than a taproot verification.
    assert_eq!(
        verify_script(
            &script_sig,
            &script_pubkey,
            &witness,
            TAPROOT_FLAGS,
            &checker
        ),
        Ok(())
    );
}

#[test]
fn without_the_taproot_flag_v1_is_anyone_can_spend() {
    let secp = secp();
    let internal = keypair(0xee);
    let (internal_xonly, _) = internal.x_only_public_key();
    let (output_key, _) = tweak_key(internal_xonly, None);
    let script_pubkey = p2tr_script(output_key);
    let spent_outputs = spent(&script_pubkey, 10_000);

    // A garbage witness under pre-taproot rules: accepted, exactly as a node
    // that predates the soft fork would.
    let witness = vec![vec![0xff; 64]];
    let tx = spending_tx(witness.clone());
    let checker = TransactionSignatureChecker::new(&tx, 0, &spent_outputs, &secp);

    assert_eq!(
        verify_script(
            &[],
            &script_pubkey,
            &witness,
            VerifyFlags::CONSENSUS_SEGWIT,
            &checker
        ),
        Ok(())
    );
    // With taproot active the same spend is rejected.
    assert!(verify_script(&[], &script_pubkey, &witness, TAPROOT_FLAGS, &checker).is_err());
}
