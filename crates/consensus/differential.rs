//! Differential tests: native engine vs `libbitcoinconsensus`.
//!
//! The native engine in `bitcrab-script` is a reimplementation of Bitcoin
//! Core's script consensus rules. Reimplementing consensus is only safe if the
//! result is checked against the reference, so every case here runs the *same*
//! transaction, the *same* spent outputs and the *same* flags through both
//! engines and asserts they agree on accept/reject.
//!
//! The two disagree only in the detail of *why* something failed — Bitcrab
//! returns a typed `ScriptError`, `libbitcoinconsensus` collapses everything to
//! a single error code — so agreement is asserted on the verdict, not the
//! reason.
//!
//! Run with:
//!
//! ```text
//! cargo test -p bitcrab-consensus --features differential-tests
//! ```
//!
//! The feature is opt-in because `libbitcoinconsensus` does not link on every
//! toolchain (it fails on MSVC with unresolved `__imp_secp256k1_*` symbols).

use bitcrab_common::types::{
    amount::Amount,
    coin::Coin,
    hash::{hash160, sha256, Txid},
    script::ScriptBuf,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
};
use bitcrab_script::{opcode::all, script_ops::push_data, sighash::Bip143Cache, VerifyFlags};
use secp256k1::{Keypair, Message, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};

use crate::engine::{ConsensusEngine, ConsensusEngineKind};

/// Run one input through both engines and require the same verdict.
fn assert_engines_agree(tx: &Transaction, coins: &[Coin], flags: VerifyFlags, case: &str) {
    let native = ConsensusEngine::new(ConsensusEngineKind::Native).with_flags(flags);
    let reference = ConsensusEngine::new(ConsensusEngineKind::CoreReference).with_flags(flags);

    let native_result = native.verify_transaction(tx, coins);
    let reference_result = reference.verify_transaction(tx, coins);

    assert_eq!(
        native_result.is_ok(),
        reference_result.is_ok(),
        "engines disagree on '{}' (flags {:#x}): native={:?} libbitcoinconsensus={:?}",
        case,
        flags.bits(),
        native_result,
        reference_result,
    );
}

struct Fixture {
    secp: Secp256k1<secp256k1::All>,
    key: SecretKey,
}

impl Fixture {
    fn new(seed: u8) -> Self {
        Self {
            secp: Secp256k1::new(),
            key: SecretKey::from_slice(&[seed; 32]).unwrap(),
        }
    }

    fn pubkey(&self) -> Vec<u8> {
        self.key.public_key(&self.secp).serialize().to_vec()
    }

    fn sign(&self, digest: [u8; 32], hash_type: u8) -> Vec<u8> {
        let sig = self
            .secp
            .sign_ecdsa(&Message::from_digest(digest), &self.key);
        let mut bytes = sig.serialize_der().to_vec();
        bytes.push(hash_type);
        bytes
    }
}

/// A spending transaction with one input and one output.
fn spending_tx(script_sig: Vec<u8>, witness: Vec<Vec<u8>>) -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_bytes([0x42; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::from_bytes(script_sig),
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

fn coin(script_pubkey: Vec<u8>, sats: u64) -> Coin {
    Coin::new(
        TxOut {
            value: Amount::from_sat(sats).unwrap(),
            script_pubkey: ScriptBuf::from_bytes(script_pubkey),
        },
        bitcrab_common::types::block::BlockHeight(1),
        false,
    )
}

const FLAG_SETS: &[VerifyFlags] = &[
    VerifyFlags::NONE,
    VerifyFlags::P2SH,
    VerifyFlags::CONSENSUS_SEGWIT,
    VerifyFlags::CONSENSUS_TAPROOT,
];

// ---------------------------------------------------------------------------
// P2PKH
// ---------------------------------------------------------------------------

#[test]
fn p2pkh_valid_and_invalid_agree() {
    let fixture = Fixture::new(0x11);
    let pubkey = fixture.pubkey();

    let mut script_pubkey = vec![all::OP_DUP, all::OP_HASH160, 0x14];
    script_pubkey.extend_from_slice(&hash160(&pubkey));
    script_pubkey.push(all::OP_EQUALVERIFY);
    script_pubkey.push(all::OP_CHECKSIG);

    // Build the signature over the real sighash.
    let unsigned = spending_tx(Vec::new(), Vec::new());
    let digest = bitcrab_script::legacy_signature_hash(&unsigned, 0, &script_pubkey, 1);
    let sig = fixture.sign(digest, 1);

    let mut script_sig = Vec::new();
    push_data(&mut script_sig, &sig);
    push_data(&mut script_sig, &pubkey);

    let tx = spending_tx(script_sig, Vec::new());
    let coins = vec![coin(script_pubkey.clone(), 10_000)];

    for &flags in FLAG_SETS {
        assert_engines_agree(&tx, &coins, flags, "valid p2pkh");
    }

    // Now corrupt the signature: both engines must reject.
    let mut bad_sig = sig.clone();
    bad_sig[10] ^= 0xff;
    let mut bad_script_sig = Vec::new();
    push_data(&mut bad_script_sig, &bad_sig);
    push_data(&mut bad_script_sig, &pubkey);
    let bad_tx = spending_tx(bad_script_sig, Vec::new());

    for &flags in FLAG_SETS {
        assert_engines_agree(&bad_tx, &coins, flags, "p2pkh with a corrupted signature");
    }

    // Wrong pubkey for the hash.
    let other = Fixture::new(0x22);
    let mut wrong_script_sig = Vec::new();
    push_data(&mut wrong_script_sig, &sig);
    push_data(&mut wrong_script_sig, &other.pubkey());
    let wrong_tx = spending_tx(wrong_script_sig, Vec::new());

    for &flags in FLAG_SETS {
        assert_engines_agree(&wrong_tx, &coins, flags, "p2pkh with the wrong pubkey");
    }
}

// ---------------------------------------------------------------------------
// Bare multisig — exercises the CHECKMULTISIG dummy quirk
// ---------------------------------------------------------------------------

#[test]
fn bare_multisig_agrees_including_the_dummy_quirk() {
    let a = Fixture::new(0x33);
    let b = Fixture::new(0x44);

    let mut script_pubkey = vec![all::OP_1];
    push_data(&mut script_pubkey, &a.pubkey());
    push_data(&mut script_pubkey, &b.pubkey());
    script_pubkey.push(all::OP_2);
    script_pubkey.push(all::OP_CHECKMULTISIG);

    let unsigned = spending_tx(Vec::new(), Vec::new());
    let digest = bitcrab_script::legacy_signature_hash(&unsigned, 0, &script_pubkey, 1);
    let sig = a.sign(digest, 1);

    let coins = vec![coin(script_pubkey.clone(), 10_000)];

    // Correct: OP_0 dummy then the signature.
    let mut script_sig = vec![all::OP_0];
    push_data(&mut script_sig, &sig);
    let tx = spending_tx(script_sig, Vec::new());
    for &flags in FLAG_SETS {
        assert_engines_agree(&tx, &coins, flags, "1-of-2 bare multisig");
    }

    // Non-empty dummy: valid without NULLDUMMY, invalid with it. Both engines
    // must make the same call under each flag set.
    let mut bad_dummy = vec![all::OP_1];
    push_data(&mut bad_dummy, &sig);
    let bad_tx = spending_tx(bad_dummy, Vec::new());
    for &flags in FLAG_SETS {
        assert_engines_agree(&bad_tx, &coins, flags, "multisig with a non-null dummy");
    }
    assert_engines_agree(
        &bad_tx,
        &coins,
        VerifyFlags::P2SH | VerifyFlags::NULLDUMMY,
        "multisig with a non-null dummy under NULLDUMMY",
    );
}

// ---------------------------------------------------------------------------
// P2SH
// ---------------------------------------------------------------------------

#[test]
fn p2sh_wrapped_checksig_agrees() {
    let fixture = Fixture::new(0x55);
    let pubkey = fixture.pubkey();

    let mut redeem = Vec::new();
    push_data(&mut redeem, &pubkey);
    redeem.push(all::OP_CHECKSIG);

    let mut script_pubkey = vec![all::OP_HASH160, 0x14];
    script_pubkey.extend_from_slice(&hash160(&redeem));
    script_pubkey.push(all::OP_EQUAL);

    // The redeemScript, not the scriptPubKey, is the scriptCode.
    let unsigned = spending_tx(Vec::new(), Vec::new());
    let digest = bitcrab_script::legacy_signature_hash(&unsigned, 0, &redeem, 1);
    let sig = fixture.sign(digest, 1);

    let mut script_sig = Vec::new();
    push_data(&mut script_sig, &sig);
    push_data(&mut script_sig, &redeem);

    let tx = spending_tx(script_sig, Vec::new());
    let coins = vec![coin(script_pubkey, 10_000)];

    for &flags in FLAG_SETS {
        assert_engines_agree(&tx, &coins, flags, "p2sh-wrapped checksig");
    }
}

#[test]
fn p2sh_with_a_mismatched_redeem_script_agrees() {
    let redeem = vec![all::OP_1];
    let mut script_pubkey = vec![all::OP_HASH160, 0x14];
    script_pubkey.extend_from_slice(&[0xab; 20]); // hash of something else
    script_pubkey.push(all::OP_EQUAL);

    let mut script_sig = Vec::new();
    push_data(&mut script_sig, &redeem);

    let tx = spending_tx(script_sig, Vec::new());
    let coins = vec![coin(script_pubkey, 10_000)];

    for &flags in FLAG_SETS {
        assert_engines_agree(&tx, &coins, flags, "p2sh hash mismatch");
    }
}

// ---------------------------------------------------------------------------
// SegWit v0 — the path that matters for signet
// ---------------------------------------------------------------------------

#[test]
fn p2wpkh_agrees() {
    let fixture = Fixture::new(0x66);
    let pubkey = fixture.pubkey();
    let key_hash = hash160(&pubkey);

    let mut script_pubkey = vec![all::OP_0, 0x14];
    script_pubkey.extend_from_slice(&key_hash);

    let amount = 10_000u64;

    // BIP 143 scriptCode for P2WPKH is the implied P2PKH script.
    let mut script_code = vec![all::OP_DUP, all::OP_HASH160, 0x14];
    script_code.extend_from_slice(&key_hash);
    script_code.push(all::OP_EQUALVERIFY);
    script_code.push(all::OP_CHECKSIG);

    let unsigned = spending_tx(Vec::new(), Vec::new());
    let cache = Bip143Cache::new(&unsigned);
    let digest = bitcrab_script::witness_v0_signature_hash(
        &unsigned,
        0,
        &script_code,
        amount as i64,
        1,
        &cache,
    );
    let sig = fixture.sign(digest, 1);

    let tx = spending_tx(Vec::new(), vec![sig.clone(), pubkey.clone()]);
    let coins = vec![coin(script_pubkey.clone(), amount)];

    assert_engines_agree(&tx, &coins, VerifyFlags::CONSENSUS_SEGWIT, "valid p2wpkh");

    // BIP 143 commits to the amount: claiming a different one must fail in both.
    let wrong_amount = vec![coin(script_pubkey.clone(), amount + 1)];
    assert_engines_agree(
        &tx,
        &wrong_amount,
        VerifyFlags::CONSENSUS_SEGWIT,
        "p2wpkh with the wrong amount",
    );

    // Corrupted signature.
    let mut bad_sig = sig;
    bad_sig[10] ^= 0xff;
    let bad_tx = spending_tx(Vec::new(), vec![bad_sig, pubkey]);
    assert_engines_agree(
        &bad_tx,
        &coins,
        VerifyFlags::CONSENSUS_SEGWIT,
        "p2wpkh with a corrupted signature",
    );
}

#[test]
fn p2wsh_agrees() {
    let fixture = Fixture::new(0x77);
    let pubkey = fixture.pubkey();

    let mut witness_script = Vec::new();
    push_data(&mut witness_script, &pubkey);
    witness_script.push(all::OP_CHECKSIG);

    let mut script_pubkey = vec![all::OP_0, 0x20];
    script_pubkey.extend_from_slice(&sha256(&witness_script));

    let amount = 25_000u64;
    let unsigned = spending_tx(Vec::new(), Vec::new());
    let cache = Bip143Cache::new(&unsigned);
    let digest = bitcrab_script::witness_v0_signature_hash(
        &unsigned,
        0,
        &witness_script,
        amount as i64,
        1,
        &cache,
    );
    let sig = fixture.sign(digest, 1);

    let tx = spending_tx(Vec::new(), vec![sig, witness_script.clone()]);
    let coins = vec![coin(script_pubkey.clone(), amount)];

    assert_engines_agree(&tx, &coins, VerifyFlags::CONSENSUS_SEGWIT, "valid p2wsh");

    // Wrong witness script for the program hash.
    let bad_tx = spending_tx(Vec::new(), vec![vec![0x00], vec![all::OP_1]]);
    assert_engines_agree(
        &bad_tx,
        &coins,
        VerifyFlags::CONSENSUS_SEGWIT,
        "p2wsh program mismatch",
    );
}

#[test]
fn witness_on_a_non_witness_output_agrees() {
    let script_pubkey = vec![all::OP_1];
    let tx = spending_tx(Vec::new(), vec![vec![0x01, 0x02]]);
    let coins = vec![coin(script_pubkey, 10_000)];

    assert_engines_agree(
        &tx,
        &coins,
        VerifyFlags::CONSENSUS_SEGWIT,
        "unexpected witness",
    );
}

// ---------------------------------------------------------------------------
// Sighash variants
// ---------------------------------------------------------------------------

#[test]
fn every_sighash_type_agrees() {
    let fixture = Fixture::new(0x88);
    let pubkey = fixture.pubkey();

    let mut script_pubkey = Vec::new();
    push_data(&mut script_pubkey, &pubkey);
    script_pubkey.push(all::OP_CHECKSIG);

    let coins = vec![coin(script_pubkey.clone(), 10_000)];

    for hash_type in [0x01u8, 0x02, 0x03, 0x81, 0x82, 0x83] {
        let unsigned = spending_tx(Vec::new(), Vec::new());
        let digest =
            bitcrab_script::legacy_signature_hash(&unsigned, 0, &script_pubkey, hash_type as u32);
        let sig = fixture.sign(digest, hash_type);

        let mut script_sig = Vec::new();
        push_data(&mut script_sig, &sig);
        let tx = spending_tx(script_sig, Vec::new());

        for &flags in FLAG_SETS {
            assert_engines_agree(
                &tx,
                &coins,
                flags,
                &format!("checksig with hash type {:#04x}", hash_type),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Pure script structure — no signatures involved
// ---------------------------------------------------------------------------

#[test]
fn structural_scripts_agree_across_flag_sets() {
    // Each case is (scriptSig, scriptPubKey, description). They cover the
    // control flow, arithmetic, hashing and failure paths of EvalScript.
    let mut cases: Vec<(Vec<u8>, Vec<u8>, &str)> = vec![
        (vec![], vec![all::OP_1], "trivially true"),
        (vec![], vec![all::OP_0], "trivially false"),
        (vec![], vec![all::OP_RETURN], "op_return"),
        (
            vec![],
            vec![all::OP_2, all::OP_3, all::OP_ADD, all::OP_5, all::OP_EQUAL],
            "2+3==5",
        ),
        (
            vec![],
            vec![all::OP_2, all::OP_3, all::OP_ADD, all::OP_6, all::OP_EQUAL],
            "2+3==6 (false)",
        ),
        (
            vec![],
            vec![
                all::OP_1,
                all::OP_IF,
                all::OP_1,
                all::OP_ELSE,
                all::OP_0,
                all::OP_ENDIF,
            ],
            "if/else true branch",
        ),
        (
            vec![],
            vec![all::OP_1, all::OP_IF, all::OP_1],
            "unbalanced conditional",
        ),
        (vec![], vec![all::OP_CAT], "disabled opcode"),
        (vec![], vec![all::OP_ADD], "stack underflow"),
        (
            vec![],
            vec![all::OP_1, all::OP_1, all::OP_EQUALVERIFY],
            "equalverify empties the stack",
        ),
        (
            vec![],
            vec![all::OP_16, all::OP_16, all::OP_NUMEQUAL],
            "16==16",
        ),
        (
            vec![],
            vec![
                all::OP_1NEGATE,
                all::OP_1,
                all::OP_ADD,
                all::OP_0,
                all::OP_NUMEQUAL,
            ],
            "-1+1==0",
        ),
        (
            vec![],
            vec![all::OP_DEPTH, all::OP_0, all::OP_EQUAL],
            "depth of an empty stack",
        ),
        (vec![], vec![all::OP_NOP; 202], "operation limit exceeded"),
        (vec![], vec![0x05, 0x01, 0x02], "truncated push"),
    ];

    // A hash round-trip.
    let preimage = b"bitcrab".to_vec();
    let mut hash_check = Vec::new();
    push_data(&mut hash_check, &preimage);
    let mut hash_script = vec![all::OP_HASH160, 0x14];
    hash_script.extend_from_slice(&hash160(&preimage));
    hash_script.push(all::OP_EQUAL);
    cases.push((hash_check, hash_script, "hash160 preimage"));

    for (script_sig, script_pubkey, description) in cases {
        let tx = spending_tx(script_sig, Vec::new());
        let coins = vec![coin(script_pubkey, 10_000)];
        for &flags in FLAG_SETS {
            assert_engines_agree(&tx, &coins, flags, description);
        }
    }
}

#[test]
fn minimaldata_and_cleanstack_flags_agree() {
    // Left-over stack elements: fine normally, rejected under CLEANSTACK.
    let tx = spending_tx(vec![all::OP_1, all::OP_1], Vec::new());
    let coins = vec![coin(vec![all::OP_1], 10_000)];

    assert_engines_agree(&tx, &coins, VerifyFlags::P2SH, "extra stack elements");
    assert_engines_agree(
        &tx,
        &coins,
        VerifyFlags::P2SH | VerifyFlags::WITNESS | VerifyFlags::CLEANSTACK,
        "extra stack elements under CLEANSTACK",
    );

    // Non-minimal push of the value 1.
    let tx = spending_tx(vec![0x01, 0x01], Vec::new());
    assert_engines_agree(&tx, &coins, VerifyFlags::P2SH, "non-minimal push");
    assert_engines_agree(
        &tx,
        &coins,
        VerifyFlags::P2SH | VerifyFlags::MINIMALDATA,
        "non-minimal push under MINIMALDATA",
    );
}

// ---------------------------------------------------------------------------
// Taproot (BIP 341 / BIP 342)
// ---------------------------------------------------------------------------

fn taproot_keypair(seed: u8) -> Keypair {
    Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[seed; 32]).unwrap(),
    )
}

/// Apply the BIP 341 tweak, returning the output key and its parity bit.
fn tweak(internal: XOnlyPublicKey, merkle_root: Option<[u8; 32]>) -> (XOnlyPublicKey, u8) {
    let mut data = internal.serialize().to_vec();
    if let Some(root) = merkle_root {
        data.extend_from_slice(&root);
    }
    let scalar =
        Scalar::from_be_bytes(bitcrab_script::taproot::tagged_hash("TapTweak", &data)).unwrap();
    let (key, parity) = internal.add_tweak(&Secp256k1::new(), &scalar).unwrap();
    (key, parity as u8)
}

fn p2tr(output_key: XOnlyPublicKey) -> Vec<u8> {
    let mut script = vec![all::OP_1, 0x20];
    script.extend_from_slice(&output_key.serialize());
    script
}

#[test]
fn taproot_key_path_agrees() {
    let secp = Secp256k1::new();
    let internal = taproot_keypair(0xa1);
    let (internal_xonly, _) = internal.x_only_public_key();
    let (output_key, _) = tweak(internal_xonly, None);

    let script_pubkey = p2tr(output_key);
    let amount = 10_000u64;
    let coins = vec![coin(script_pubkey.clone(), amount)];
    let spent_outputs: Vec<_> = coins.iter().map(|c| c.output.clone()).collect();

    let scalar = Scalar::from_be_bytes(bitcrab_script::taproot::tagged_hash(
        "TapTweak",
        &internal_xonly.serialize(),
    ))
    .unwrap();
    let tweaked = internal.add_xonly_tweak(&secp, &scalar).unwrap();

    let unsigned = spending_tx(Vec::new(), Vec::new());
    let exec_data = bitcrab_script::ScriptExecutionData::new();
    let cache = bitcrab_script::TaprootCache::new(&unsigned, &spent_outputs);
    let digest = bitcrab_script::taproot_signature_hash(
        &unsigned,
        0,
        &spent_outputs,
        0x00,
        0,
        &exec_data,
        &cache,
    )
    .unwrap();

    let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &tweaked);
    let tx = spending_tx(Vec::new(), vec![sig.serialize().to_vec()]);

    assert_engines_agree(
        &tx,
        &coins,
        VerifyFlags::CONSENSUS_TAPROOT,
        "valid taproot key-path spend",
    );

    // A garbage signature of the right length must be rejected by both.
    let bad = spending_tx(Vec::new(), vec![vec![0xab; 64]]);
    assert_engines_agree(
        &bad,
        &coins,
        VerifyFlags::CONSENSUS_TAPROOT,
        "taproot key-path with a bogus signature",
    );

    // And before taproot activates, both must treat it as anyone-can-spend.
    assert_engines_agree(
        &bad,
        &coins,
        VerifyFlags::CONSENSUS_SEGWIT,
        "taproot output under pre-taproot rules",
    );
}

#[test]
fn taproot_script_path_agrees() {
    let internal = taproot_keypair(0xb2);
    let (internal_xonly, _) = internal.x_only_public_key();

    let leaf_script = vec![all::OP_1];
    let leaf_hash = bitcrab_script::taproot::compute_tapleaf_hash(
        bitcrab_script::taproot::TAPROOT_LEAF_TAPSCRIPT,
        &leaf_script,
    );
    let (output_key, parity) = tweak(internal_xonly, Some(leaf_hash));

    let script_pubkey = p2tr(output_key);
    let coins = vec![coin(script_pubkey.clone(), 10_000)];

    let mut control = vec![bitcrab_script::taproot::TAPROOT_LEAF_TAPSCRIPT | parity];
    control.extend_from_slice(&internal_xonly.serialize());

    let tx = spending_tx(Vec::new(), vec![leaf_script.clone(), control.clone()]);
    assert_engines_agree(
        &tx,
        &coins,
        VerifyFlags::CONSENSUS_TAPROOT,
        "valid taproot script-path spend",
    );

    // Revealing a leaf that is not in the tree.
    let wrong = spending_tx(Vec::new(), vec![vec![all::OP_2], control]);
    assert_engines_agree(
        &wrong,
        &coins,
        VerifyFlags::CONSENSUS_TAPROOT,
        "taproot script-path with an uncommitted leaf",
    );
}

#[test]
fn tapscript_rules_agree() {
    let internal = taproot_keypair(0xc3);
    let (internal_xonly, _) = internal.x_only_public_key();

    // Each leaf exercises a BIP 342 rule that differs from legacy script.
    let leaves: Vec<(Vec<u8>, &str)> = vec![
        (
            vec![all::OP_0, all::OP_0, all::OP_0, all::OP_CHECKMULTISIG],
            "CHECKMULTISIG is disabled in tapscript",
        ),
        (vec![80u8, all::OP_RETURN], "OP_SUCCESS80"),
        (vec![all::OP_1, all::OP_1, all::OP_EQUAL], "plain equality"),
    ];

    for (leaf_script, description) in leaves {
        let leaf_hash = bitcrab_script::taproot::compute_tapleaf_hash(
            bitcrab_script::taproot::TAPROOT_LEAF_TAPSCRIPT,
            &leaf_script,
        );
        let (output_key, parity) = tweak(internal_xonly, Some(leaf_hash));

        let mut control = vec![bitcrab_script::taproot::TAPROOT_LEAF_TAPSCRIPT | parity];
        control.extend_from_slice(&internal_xonly.serialize());

        let script_pubkey = p2tr(output_key);
        let coins = vec![coin(script_pubkey, 10_000)];
        let tx = spending_tx(Vec::new(), vec![leaf_script, control]);

        assert_engines_agree(&tx, &coins, VerifyFlags::CONSENSUS_TAPROOT, description);
    }
}
