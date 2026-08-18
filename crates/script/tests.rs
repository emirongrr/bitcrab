//! Interpreter tests.
//!
//! These exercise the native engine directly. The differential tests that
//! compare it against `libbitcoinconsensus` live in `bitcrab-consensus`, which
//! is where that dependency is available.

use crate::checker::{NullSignatureChecker, SigVersion, SignatureChecker};
use crate::error::ScriptError;
use crate::flags::VerifyFlags;
use crate::interpreter::{eval_script, verify_script};
use crate::num::{cast_to_bool, ScriptNum};
use crate::opcode::all;
use crate::script_ops::push_data;
use bitcrab_common::types::hash::{hash160, sha256};

/// A checker that accepts any non-empty signature.
///
/// Lets script *structure* be tested without constructing real keys; the
/// cryptography itself is covered by the transaction-level tests.
struct AlwaysValidChecker;

impl SignatureChecker for AlwaysValidChecker {
    fn check_ecdsa_signature(&self, sig: &[u8], _: &[u8], _: &[u8], _: SigVersion) -> bool {
        !sig.is_empty()
    }
    fn check_lock_time(&self, _: ScriptNum) -> bool {
        true
    }
    fn check_sequence(&self, _: ScriptNum) -> bool {
        true
    }
}

fn run(script: &[u8]) -> Result<Vec<Vec<u8>>, ScriptError> {
    let mut stack = Vec::new();
    eval_script(
        &mut stack,
        script,
        VerifyFlags::NONE,
        &NullSignatureChecker,
        SigVersion::Base,
    )?;
    Ok(stack)
}

fn run_flags(script: &[u8], flags: VerifyFlags) -> Result<Vec<Vec<u8>>, ScriptError> {
    let mut stack = Vec::new();
    eval_script(
        &mut stack,
        script,
        flags,
        &NullSignatureChecker,
        SigVersion::Base,
    )?;
    Ok(stack)
}

fn num(value: i64) -> Vec<u8> {
    ScriptNum(value).encode()
}

// ---------------------------------------------------------------------------
// Arithmetic and stack
// ---------------------------------------------------------------------------

#[test]
fn arithmetic_produces_core_compatible_results() {
    // OP_2 OP_3 OP_ADD -> 5
    let stack = run(&[all::OP_2, all::OP_3, all::OP_ADD]).unwrap();
    assert_eq!(stack, vec![num(5)]);

    // OP_5 OP_3 OP_SUB -> 2
    let stack = run(&[all::OP_5, all::OP_3, all::OP_SUB]).unwrap();
    assert_eq!(stack, vec![num(2)]);

    // Negative results encode with the sign bit.
    let stack = run(&[all::OP_3, all::OP_5, all::OP_SUB]).unwrap();
    assert_eq!(stack, vec![num(-2)]);
}

#[test]
fn comparison_opcodes_push_boolean_elements() {
    assert_eq!(
        run(&[all::OP_3, all::OP_5, all::OP_LESSTHAN]).unwrap(),
        vec![vec![1]]
    );
    assert_eq!(
        run(&[all::OP_5, all::OP_3, all::OP_LESSTHAN]).unwrap(),
        vec![Vec::<u8>::new()]
    );
    // OP_WITHIN is [min, max).
    assert_eq!(
        run(&[all::OP_3, all::OP_1, all::OP_5, all::OP_WITHIN]).unwrap(),
        vec![vec![1]]
    );
    assert_eq!(
        run(&[all::OP_5, all::OP_1, all::OP_5, all::OP_WITHIN]).unwrap(),
        vec![Vec::<u8>::new()]
    );
}

#[test]
fn stack_manipulation_opcodes() {
    // OP_1 OP_2 OP_SWAP -> [2, 1]
    assert_eq!(
        run(&[all::OP_1, all::OP_2, all::OP_SWAP]).unwrap(),
        vec![num(2), num(1)]
    );
    // OP_1 OP_2 OP_OVER -> [1, 2, 1]
    assert_eq!(
        run(&[all::OP_1, all::OP_2, all::OP_OVER]).unwrap(),
        vec![num(1), num(2), num(1)]
    );
    // OP_1 OP_2 OP_3 OP_ROT -> [2, 3, 1]
    assert_eq!(
        run(&[all::OP_1, all::OP_2, all::OP_3, all::OP_ROT]).unwrap(),
        vec![num(2), num(3), num(1)]
    );
    // OP_1 OP_2 OP_TUCK -> [2, 1, 2]
    assert_eq!(
        run(&[all::OP_1, all::OP_2, all::OP_TUCK]).unwrap(),
        vec![num(2), num(1), num(2)]
    );
    // OP_1 OP_2 OP_NIP -> [2]
    assert_eq!(
        run(&[all::OP_1, all::OP_2, all::OP_NIP]).unwrap(),
        vec![num(2)]
    );
}

#[test]
fn pick_and_roll_index_from_the_top() {
    // [1,2,3] OP_2 OP_PICK -> copies the element 2 below the top (1)
    assert_eq!(
        run(&[all::OP_1, all::OP_2, all::OP_3, all::OP_2, all::OP_PICK]).unwrap(),
        vec![num(1), num(2), num(3), num(1)]
    );
    // OP_ROLL moves it instead of copying.
    assert_eq!(
        run(&[all::OP_1, all::OP_2, all::OP_3, all::OP_2, all::OP_ROLL]).unwrap(),
        vec![num(2), num(3), num(1)]
    );
    // Out-of-range index is an error, not a panic.
    assert_eq!(
        run(&[all::OP_1, all::OP_5, all::OP_PICK]),
        Err(ScriptError::InvalidStackOperation)
    );
}

#[test]
fn altstack_round_trips() {
    assert_eq!(
        run(&[
            all::OP_1,
            all::OP_TOALTSTACK,
            all::OP_2,
            all::OP_FROMALTSTACK
        ])
        .unwrap(),
        vec![num(2), num(1)]
    );
    // Popping an empty altstack is a specific error.
    assert_eq!(
        run(&[all::OP_FROMALTSTACK]),
        Err(ScriptError::InvalidAltstackOperation)
    );
}

#[test]
fn underflow_is_an_error_not_a_panic() {
    assert_eq!(run(&[all::OP_ADD]), Err(ScriptError::InvalidStackOperation));
    assert_eq!(run(&[all::OP_DUP]), Err(ScriptError::InvalidStackOperation));
    assert_eq!(
        run(&[all::OP_1, all::OP_ADD]),
        Err(ScriptError::InvalidStackOperation)
    );
}

// ---------------------------------------------------------------------------
// Conditionals
// ---------------------------------------------------------------------------

#[test]
fn conditionals_select_the_right_branch() {
    // OP_1 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF -> 2
    let script = [
        all::OP_1,
        all::OP_IF,
        all::OP_2,
        all::OP_ELSE,
        all::OP_3,
        all::OP_ENDIF,
    ];
    assert_eq!(run(&script).unwrap(), vec![num(2)]);

    // OP_0 takes the else branch.
    let script = [
        all::OP_0,
        all::OP_IF,
        all::OP_2,
        all::OP_ELSE,
        all::OP_3,
        all::OP_ENDIF,
    ];
    assert_eq!(run(&script).unwrap(), vec![num(3)]);

    // OP_NOTIF inverts.
    let script = [
        all::OP_0,
        all::OP_NOTIF,
        all::OP_2,
        all::OP_ELSE,
        all::OP_3,
        all::OP_ENDIF,
    ];
    assert_eq!(run(&script).unwrap(), vec![num(2)]);
}

#[test]
fn nested_conditionals_track_depth() {
    // 1 IF (1 IF 7 ELSE 8 ENDIF) ELSE 9 ENDIF -> 7
    let script = [
        all::OP_1,
        all::OP_IF,
        all::OP_1,
        all::OP_IF,
        all::OP_7,
        all::OP_ELSE,
        all::OP_8,
        all::OP_ENDIF,
        all::OP_ELSE,
        all::OP_9,
        all::OP_ENDIF,
    ];
    assert_eq!(run(&script).unwrap(), vec![num(7)]);
}

#[test]
fn unbalanced_conditionals_are_rejected() {
    assert_eq!(
        run(&[all::OP_1, all::OP_IF, all::OP_2]),
        Err(ScriptError::UnbalancedConditional)
    );
    assert_eq!(
        run(&[all::OP_ENDIF]),
        Err(ScriptError::UnbalancedConditional)
    );
    assert_eq!(
        run(&[all::OP_ELSE]),
        Err(ScriptError::UnbalancedConditional)
    );
}

#[test]
fn unexecuted_branches_do_not_run_their_opcodes() {
    // The OP_ADD in the dead branch would underflow if it executed.
    let script = [
        all::OP_1,
        all::OP_IF,
        all::OP_2,
        all::OP_ELSE,
        all::OP_ADD,
        all::OP_ENDIF,
    ];
    assert_eq!(run(&script).unwrap(), vec![num(2)]);
}

#[test]
fn disabled_opcodes_fail_even_inside_a_dead_branch() {
    // Bitcoin Core checks IsOpcodeDisabled before the fExec test, so OP_CAT in
    // an untaken branch still kills the script.
    let script = [
        all::OP_1,
        all::OP_IF,
        all::OP_2,
        all::OP_ELSE,
        all::OP_CAT,
        all::OP_ENDIF,
    ];
    assert_eq!(run(&script), Err(ScriptError::DisabledOpcode));
}

// ---------------------------------------------------------------------------
// Crypto opcodes
// ---------------------------------------------------------------------------

#[test]
fn hash_opcodes_match_the_hash_functions() {
    let data = b"bitcrab";
    let mut script = Vec::new();
    push_data(&mut script, data);
    script.push(all::OP_HASH160);
    assert_eq!(run(&script).unwrap(), vec![hash160(data).to_vec()]);

    let mut script = Vec::new();
    push_data(&mut script, data);
    script.push(all::OP_SHA256);
    assert_eq!(run(&script).unwrap(), vec![sha256(data).to_vec()]);
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

#[test]
fn operation_limit_is_enforced() {
    // MAX_OPS_PER_SCRIPT is 201; OP_NOP counts, pushes do not.
    let ok = vec![all::OP_NOP; 201];
    assert!(run(&ok).is_ok());

    let too_many = vec![all::OP_NOP; 202];
    assert_eq!(run(&too_many), Err(ScriptError::OpCount));
}

#[test]
fn pushes_do_not_count_against_the_operation_limit() {
    let mut script = Vec::new();
    for _ in 0..300 {
        script.push(all::OP_1);
        script.push(all::OP_DROP);
    }
    // 300 OP_DROPs exceeds 201 even though the OP_1s are free.
    assert_eq!(run(&script), Err(ScriptError::OpCount));
}

#[test]
fn stack_size_limit_is_enforced() {
    // Must grow the stack with pushes: OP_DUP counts against the 201-operation
    // budget and would trip OpCount long before the stack limit.
    let script = vec![all::OP_1; 1001];
    assert_eq!(run(&script), Err(ScriptError::StackSize));

    let script = vec![all::OP_1; 1000];
    assert!(
        run(&script).is_ok(),
        "1000 elements is the limit, not past it"
    );
}

#[test]
fn oversized_push_is_rejected() {
    let mut script = Vec::new();
    push_data(&mut script, &vec![0u8; 521]);
    assert_eq!(run(&script), Err(ScriptError::PushSize));

    let mut script = Vec::new();
    push_data(&mut script, &vec![0u8; 520]);
    assert!(run(&script).is_ok(), "520 bytes is the limit, not past it");
}

#[test]
fn minimaldata_rejects_wasteful_pushes() {
    // Pushing 1 as a one-byte push instead of OP_1.
    let script = vec![0x01, 0x01];
    assert!(run_flags(&script, VerifyFlags::NONE).is_ok());
    assert_eq!(
        run_flags(&script, VerifyFlags::MINIMALDATA),
        Err(ScriptError::MinimalData)
    );
}

// ---------------------------------------------------------------------------
// VerifyScript: P2PKH / P2SH / witness plumbing
// ---------------------------------------------------------------------------

#[test]
fn bare_checksig_succeeds_with_a_permissive_checker() {
    let mut script_sig = Vec::new();
    push_data(&mut script_sig, &[0x30; 71]); // signature-shaped
    let mut script_pubkey = Vec::new();
    push_data(&mut script_pubkey, &[0x02; 33]);
    script_pubkey.push(all::OP_CHECKSIG);

    assert_eq!(
        verify_script(
            &script_sig,
            &script_pubkey,
            &[],
            VerifyFlags::NONE,
            &AlwaysValidChecker
        ),
        Ok(())
    );
}

#[test]
fn p2sh_evaluates_the_redeem_script() {
    // redeemScript: OP_1 (trivially true)
    let redeem = vec![all::OP_1];
    let mut script_sig = Vec::new();
    push_data(&mut script_sig, &redeem);

    let mut script_pubkey = vec![all::OP_HASH160, 0x14];
    script_pubkey.extend_from_slice(&hash160(&redeem));
    script_pubkey.push(all::OP_EQUAL);

    assert_eq!(
        verify_script(
            &script_sig,
            &script_pubkey,
            &[],
            VerifyFlags::P2SH,
            &NullSignatureChecker
        ),
        Ok(())
    );
}

#[test]
fn p2sh_rejects_a_redeem_script_that_evaluates_false() {
    let redeem = vec![all::OP_0];
    let mut script_sig = Vec::new();
    push_data(&mut script_sig, &redeem);

    let mut script_pubkey = vec![all::OP_HASH160, 0x14];
    script_pubkey.extend_from_slice(&hash160(&redeem));
    script_pubkey.push(all::OP_EQUAL);

    assert_eq!(
        verify_script(
            &script_sig,
            &script_pubkey,
            &[],
            VerifyFlags::P2SH,
            &NullSignatureChecker
        ),
        Err(ScriptError::EvalFalse)
    );
}

#[test]
fn p2sh_requires_a_push_only_script_sig() {
    let redeem = vec![all::OP_1];
    let mut script_sig = Vec::new();
    push_data(&mut script_sig, &redeem);
    script_sig.push(all::OP_NOP); // no longer push-only

    let mut script_pubkey = vec![all::OP_HASH160, 0x14];
    script_pubkey.extend_from_slice(&hash160(&redeem));
    script_pubkey.push(all::OP_EQUAL);

    assert_eq!(
        verify_script(
            &script_sig,
            &script_pubkey,
            &[],
            VerifyFlags::P2SH,
            &NullSignatureChecker
        ),
        Err(ScriptError::SigPushOnly)
    );
}

#[test]
fn p2wsh_hash_mismatch_is_detected() {
    let witness_script = vec![all::OP_1];
    let mut script_pubkey = vec![all::OP_0, 0x20];
    script_pubkey.extend_from_slice(&[0xff; 32]); // wrong hash

    let witness = vec![witness_script];
    assert_eq!(
        verify_script(
            &[],
            &script_pubkey,
            &witness,
            VerifyFlags::P2SH | VerifyFlags::WITNESS,
            &NullSignatureChecker
        ),
        Err(ScriptError::WitnessProgramMismatch)
    );
}

#[test]
fn p2wsh_with_the_correct_hash_evaluates_the_witness_script() {
    let witness_script = vec![all::OP_1];
    let mut script_pubkey = vec![all::OP_0, 0x20];
    script_pubkey.extend_from_slice(&sha256(&witness_script));

    let witness = vec![witness_script];
    assert_eq!(
        verify_script(
            &[],
            &script_pubkey,
            &witness,
            VerifyFlags::P2SH | VerifyFlags::WITNESS,
            &NullSignatureChecker
        ),
        Ok(())
    );
}

#[test]
fn witness_program_requires_an_empty_script_sig() {
    let witness_script = vec![all::OP_1];
    let mut script_pubkey = vec![all::OP_0, 0x20];
    script_pubkey.extend_from_slice(&sha256(&witness_script));

    assert_eq!(
        verify_script(
            &[all::OP_1],
            &script_pubkey,
            &[witness_script],
            VerifyFlags::P2SH | VerifyFlags::WITNESS,
            &NullSignatureChecker
        ),
        Err(ScriptError::WitnessMalleated)
    );
}

#[test]
fn witness_on_a_non_witness_output_is_rejected() {
    assert_eq!(
        verify_script(
            &[],
            &[all::OP_1],
            &[vec![0x01]],
            VerifyFlags::P2SH | VerifyFlags::WITNESS,
            &NullSignatureChecker
        ),
        Err(ScriptError::WitnessUnexpected)
    );
    // And without the WITNESS flag at all.
    assert_eq!(
        verify_script(
            &[],
            &[all::OP_1],
            &[vec![0x01]],
            VerifyFlags::NONE,
            &NullSignatureChecker
        ),
        Err(ScriptError::WitnessUnexpected)
    );
}

#[test]
fn unknown_witness_versions_are_anyone_can_spend_but_discourageable() {
    let mut script_pubkey = vec![all::OP_1, 0x20]; // v1 = taproot
    script_pubkey.extend_from_slice(&[0x44; 32]);

    // Without the discourage flag a pre-taproot node accepts it.
    assert_eq!(
        verify_script(
            &[],
            &script_pubkey,
            &[vec![0x01]],
            VerifyFlags::P2SH | VerifyFlags::WITNESS,
            &NullSignatureChecker
        ),
        Ok(())
    );

    // With it, the upgrade path is refused.
    assert_eq!(
        verify_script(
            &[],
            &script_pubkey,
            &[vec![0x01]],
            VerifyFlags::P2SH
                | VerifyFlags::WITNESS
                | VerifyFlags::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
            &NullSignatureChecker
        ),
        Err(ScriptError::DiscourageUpgradableWitnessProgram)
    );
}

#[test]
fn cleanstack_requires_exactly_one_leftover_element() {
    let flags = VerifyFlags::P2SH | VerifyFlags::WITNESS | VerifyFlags::CLEANSTACK;
    // Two elements left over.
    assert_eq!(
        verify_script(
            &[all::OP_1],
            &[all::OP_1],
            &[],
            flags,
            &NullSignatureChecker
        ),
        Err(ScriptError::CleanStack)
    );
    assert_eq!(
        verify_script(&[], &[all::OP_1], &[], flags, &NullSignatureChecker),
        Ok(())
    );
}

// ---------------------------------------------------------------------------
// CHECKMULTISIG quirks
// ---------------------------------------------------------------------------

#[test]
fn checkmultisig_pops_the_extra_dummy_element() {
    // OP_0 <sig> OP_1 <pubkey> OP_1 OP_CHECKMULTISIG
    let mut script = vec![all::OP_0];
    push_data(&mut script, &[0x30; 71]);
    script.push(all::OP_1);
    push_data(&mut script, &[0x02; 33]);
    script.push(all::OP_1);
    script.push(all::OP_CHECKMULTISIG);

    let mut stack = Vec::new();
    eval_script(
        &mut stack,
        &script,
        VerifyFlags::NONE,
        &AlwaysValidChecker,
        SigVersion::Base,
    )
    .unwrap();
    assert_eq!(stack, vec![vec![1]], "the dummy must have been consumed");
}

#[test]
fn nulldummy_rejects_a_non_empty_dummy() {
    // Same as above but with OP_1 as the dummy instead of OP_0.
    let mut script = vec![all::OP_1];
    push_data(&mut script, &[0x30; 71]);
    script.push(all::OP_1);
    push_data(&mut script, &[0x02; 33]);
    script.push(all::OP_1);
    script.push(all::OP_CHECKMULTISIG);

    let mut stack = Vec::new();
    let result = eval_script(
        &mut stack,
        &script,
        VerifyFlags::NULLDUMMY,
        &AlwaysValidChecker,
        SigVersion::Base,
    );
    assert_eq!(result, Err(ScriptError::SigNullDummy));
}

#[test]
fn checkmultisig_rejects_more_than_20_keys() {
    let mut script = vec![all::OP_0];
    push_data(&mut script, &num(21));
    script.push(all::OP_CHECKMULTISIG);

    let mut stack = Vec::new();
    let result = eval_script(
        &mut stack,
        &script,
        VerifyFlags::NONE,
        &AlwaysValidChecker,
        SigVersion::Base,
    );
    assert_eq!(result, Err(ScriptError::PubkeyCount));
}

#[test]
fn checkmultisig_rejects_more_sigs_than_keys() {
    // 1 key, 2 signatures requested.
    let mut script = vec![all::OP_0];
    push_data(&mut script, &[0x30; 71]);
    push_data(&mut script, &[0x30; 71]);
    script.push(all::OP_2); // sig count
    push_data(&mut script, &[0x02; 33]);
    script.push(all::OP_1); // key count
    script.push(all::OP_CHECKMULTISIG);

    let mut stack = Vec::new();
    let result = eval_script(
        &mut stack,
        &script,
        VerifyFlags::NONE,
        &AlwaysValidChecker,
        SigVersion::Base,
    );
    assert_eq!(result, Err(ScriptError::SigCount));
}

// ---------------------------------------------------------------------------
// Locktime
// ---------------------------------------------------------------------------

#[test]
fn cltv_is_a_nop_before_activation() {
    let mut script = Vec::new();
    push_data(&mut script, &num(500));
    script.push(all::OP_CHECKLOCKTIMEVERIFY);

    // Not activated: behaves as OP_NOP2 and leaves the stack alone.
    let stack = run_flags(&script, VerifyFlags::NONE).unwrap();
    assert_eq!(stack, vec![num(500)]);

    // Not activated but discouraged: hard error.
    assert_eq!(
        run_flags(&script, VerifyFlags::DISCOURAGE_UPGRADABLE_NOPS),
        Err(ScriptError::DiscourageUpgradableNops)
    );
}

#[test]
fn cltv_rejects_negative_locktimes() {
    let mut script = Vec::new();
    push_data(&mut script, &num(-1));
    script.push(all::OP_CHECKLOCKTIMEVERIFY);

    let mut stack = Vec::new();
    let result = eval_script(
        &mut stack,
        &script,
        VerifyFlags::CHECKLOCKTIMEVERIFY,
        &AlwaysValidChecker,
        SigVersion::Base,
    );
    assert_eq!(result, Err(ScriptError::NegativeLocktime));
}

#[test]
fn cltv_leaves_its_argument_on_the_stack() {
    // Unlike OP_VERIFY, CLTV does not pop — scripts rely on a following DROP.
    let mut script = Vec::new();
    push_data(&mut script, &num(500));
    script.push(all::OP_CHECKLOCKTIMEVERIFY);

    let mut stack = Vec::new();
    eval_script(
        &mut stack,
        &script,
        VerifyFlags::CHECKLOCKTIMEVERIFY,
        &AlwaysValidChecker,
        SigVersion::Base,
    )
    .unwrap();
    assert_eq!(stack, vec![num(500)]);
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

#[test]
fn op_return_always_fails() {
    assert_eq!(run(&[all::OP_RETURN]), Err(ScriptError::OpReturn));
    assert_eq!(
        run(&[all::OP_1, all::OP_RETURN]),
        Err(ScriptError::OpReturn)
    );
}

#[test]
fn op_verify_consumes_and_checks() {
    assert_eq!(
        run(&[all::OP_1, all::OP_VERIFY]).unwrap(),
        Vec::<Vec<u8>>::new()
    );
    assert_eq!(run(&[all::OP_0, all::OP_VERIFY]), Err(ScriptError::Verify));
}

#[test]
fn empty_script_leaves_an_empty_stack() {
    assert_eq!(run(&[]).unwrap(), Vec::<Vec<u8>>::new());
}

#[test]
fn script_larger_than_the_limit_is_rejected() {
    let script = vec![all::OP_NOP; 10_001];
    assert_eq!(run(&script), Err(ScriptError::ScriptSize));
}

#[test]
fn verify_script_reports_eval_false_for_a_false_result() {
    // This is the case the old engine silently accepted: verify_script used to
    // return Ok(false) and the caller discarded the bool.
    assert_eq!(
        verify_script(
            &[],
            &[all::OP_0],
            &[],
            VerifyFlags::NONE,
            &NullSignatureChecker
        ),
        Err(ScriptError::EvalFalse)
    );
    assert!(!cast_to_bool(&[]));
}
