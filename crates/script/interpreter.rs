//! Bitcoin Script interpreter.
//!
//! Bitcoin Core: `EvalScript()` and `VerifyScript()` in
//! `src/script/interpreter.cpp`.
//!
//! This is the native replacement for `libbitcoinconsensus`. The structure
//! deliberately follows Core statement for statement — same order of checks,
//! same error at each failure point — because any reordering is a potential
//! consensus split. Where Core has a quirk (the `CHECKMULTISIG` off-by-one pop,
//! the `SIGHASH_SINGLE` bug, `FindAndDelete`), it is reproduced rather than
//! corrected.
//!
//! Covered: all enabled opcodes, conditionals, altstack, arithmetic, P2SH
//! (BIP 16), CLTV/CSV (BIP 65/112), witness v0 — P2WPKH and P2WSH with BIP 143
//! hashing — and taproot: BIP 341 key-path and script-path spends, plus BIP 342
//! tapscript with OP_CHECKSIGADD, OP_SUCCESSx and the sigops budget.

use bitcrab_common::constants::{MAX_OPS_PER_SCRIPT, MAX_SCRIPT_ELEMENT_SIZE, MAX_SCRIPT_SIZE};
use bitcrab_common::types::hash::{hash160, hash256, ripemd160, sha1, sha256};

use crate::checker::{SigVersion, SignatureChecker};
use crate::error::{ScriptError, ScriptResult};
use crate::flags::VerifyFlags;
use crate::num::{cast_to_bool, ScriptNum, DEFAULT_MAX_NUM_SIZE};
use crate::opcode::all;
use crate::script_ops::{
    check_minimal_push, contains_codeseparator, find_and_delete, is_pay_to_script_hash,
    is_push_only, parse_witness_program, push_data, Instructions,
};
use crate::sig::{check_pubkey_encoding, check_signature_encoding};
use crate::taproot::{
    compute_tapleaf_hash, is_op_success, parse_control_block, verify_taproot_commitment,
    write_compact_size, ScriptExecutionData, ANNEX_TAG, TAPROOT_LEAF_MASK, TAPROOT_LEAF_TAPSCRIPT,
    VALIDATION_WEIGHT_OFFSET, VALIDATION_WEIGHT_PER_SIGOP_PASSED, WITNESS_V1_TAPROOT_SIZE,
};

/// Bitcoin Core: `MAX_STACK_SIZE` — main and alt stack combined.
const MAX_STACK_SIZE: usize = 1000;
/// Bitcoin Core: `MAX_PUBKEYS_PER_MULTISIG`.
const MAX_PUBKEYS_PER_MULTISIG: i64 = 20;
/// Bitcoin Core: `WITNESS_V0_SCRIPTHASH_SIZE`.
const WITNESS_V0_SCRIPTHASH_SIZE: usize = 32;
/// Bitcoin Core: `WITNESS_V0_KEYHASH_SIZE`.
const WITNESS_V0_KEYHASH_SIZE: usize = 20;
/// Bitcoin Core: `OP_CHECKSIGADD`, added by BIP 342.
const OP_CHECKSIGADD: u8 = 0xba;

type Stack = Vec<Vec<u8>>;

/// Evaluate a script with no taproot execution state.
pub fn eval_script(
    stack: &mut Stack,
    script: &[u8],
    flags: VerifyFlags,
    checker: &dyn SignatureChecker,
    sig_version: SigVersion,
) -> ScriptResult<()> {
    let mut exec_data = ScriptExecutionData::new();
    eval_script_with_data(stack, script, flags, checker, sig_version, &mut exec_data)
}

/// Evaluate a single script against `stack`.
///
/// Bitcoin Core: `EvalScript()`.
pub fn eval_script_with_data(
    stack: &mut Stack,
    script: &[u8],
    flags: VerifyFlags,
    checker: &dyn SignatureChecker,
    sig_version: SigVersion,
    exec_data: &mut ScriptExecutionData,
) -> ScriptResult<()> {
    // BIP 342 lifts the 10 000-byte script limit and the operation count;
    // tapscript is bounded by block weight and the sigops budget instead.
    let legacy_limits = matches!(sig_version, SigVersion::Base | SigVersion::WitnessV0);
    if legacy_limits && script.len() > MAX_SCRIPT_SIZE {
        return Err(ScriptError::ScriptSize);
    }

    let require_minimal = flags.contains(VerifyFlags::MINIMALDATA);
    let mut altstack: Stack = Vec::new();
    let mut condition_stack: Vec<bool> = Vec::new();
    let mut op_count = 0usize;
    // Offset of the most recent OP_CODESEPARATOR; scriptCode for signature
    // checks starts here.
    let mut last_codeseparator = 0usize;

    for instruction in Instructions::new(script) {
        let instruction = instruction?;
        let opcode = instruction.opcode;
        let byte = opcode.to_u8();

        let executing = condition_stack.iter().all(|branch| *branch);

        if instruction.data.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(ScriptError::PushSize);
        }

        if legacy_limits && opcode.counts_towards_op_limit() {
            op_count += 1;
            if op_count > MAX_OPS_PER_SCRIPT {
                return Err(ScriptError::OpCount);
            }
        }

        // Disabled opcodes fail the script even inside a branch that is not
        // taken. Core checks this before the `fExec` test.
        if opcode.is_disabled() {
            return Err(ScriptError::DisabledOpcode);
        }

        if !executing && !(all::OP_IF..=all::OP_ENDIF).contains(&byte) {
            continue;
        }

        if byte <= all::OP_PUSHDATA4 {
            if require_minimal && !check_minimal_push(instruction.data, opcode) {
                return Err(ScriptError::MinimalData);
            }
            stack.push(instruction.data.to_vec());
        } else {
            match byte {
                // ----------------------------------------------------- push N
                all::OP_1NEGATE | all::OP_1..=all::OP_16 => {
                    let value = opcode.decode_op_n().ok_or(ScriptError::BadOpcode)?;
                    stack.push(ScriptNum(value).encode());
                }

                // --------------------------------------------------- control
                all::OP_NOP => {}

                all::OP_CHECKLOCKTIMEVERIFY => {
                    if !flags.contains(VerifyFlags::CHECKLOCKTIMEVERIFY) {
                        // Not yet activated: behaves as a NOP.
                        if flags.contains(VerifyFlags::DISCOURAGE_UPGRADABLE_NOPS) {
                            return Err(ScriptError::DiscourageUpgradableNops);
                        }
                        continue;
                    }
                    let top = stack_top(stack, 1)?;
                    // BIP 65 permits 5 bytes so timestamps past 2038 fit.
                    let lock_time = ScriptNum::decode(top, require_minimal, 5)?;
                    if lock_time.as_i64() < 0 {
                        return Err(ScriptError::NegativeLocktime);
                    }
                    if !checker.check_lock_time(lock_time) {
                        return Err(ScriptError::UnsatisfiedLocktime);
                    }
                }

                all::OP_CHECKSEQUENCEVERIFY => {
                    if !flags.contains(VerifyFlags::CHECKSEQUENCEVERIFY) {
                        if flags.contains(VerifyFlags::DISCOURAGE_UPGRADABLE_NOPS) {
                            return Err(ScriptError::DiscourageUpgradableNops);
                        }
                        continue;
                    }
                    let top = stack_top(stack, 1)?;
                    let sequence = ScriptNum::decode(top, require_minimal, 5)?;
                    if sequence.as_i64() < 0 {
                        return Err(ScriptError::NegativeLocktime);
                    }
                    // The disable bit makes the check a no-op rather than a failure.
                    if sequence.as_i64() & crate::checker::SEQUENCE_LOCKTIME_DISABLE_FLAG == 0
                        && !checker.check_sequence(sequence)
                    {
                        return Err(ScriptError::UnsatisfiedLocktime);
                    }
                }

                all::OP_NOP1 | all::OP_NOP4..=all::OP_NOP10 => {
                    if flags.contains(VerifyFlags::DISCOURAGE_UPGRADABLE_NOPS) {
                        return Err(ScriptError::DiscourageUpgradableNops);
                    }
                }

                all::OP_IF | all::OP_NOTIF => {
                    let mut value = false;
                    if executing {
                        let top = pop(stack)?;
                        let non_minimal = top.len() > 1 || (top.len() == 1 && top[0] != 1);
                        if sig_version == SigVersion::Tapscript {
                            // BIP 342 makes minimal IF a consensus rule rather
                            // than a policy flag.
                            if non_minimal {
                                return Err(ScriptError::TapscriptMinimalIf);
                            }
                        } else if sig_version == SigVersion::WitnessV0
                            && flags.contains(VerifyFlags::MINIMALIF)
                            && non_minimal
                        {
                            return Err(ScriptError::MinimalIf);
                        }
                        value = cast_to_bool(&top);
                        if byte == all::OP_NOTIF {
                            value = !value;
                        }
                    }
                    condition_stack.push(value);
                }

                all::OP_ELSE => {
                    let last = condition_stack
                        .last_mut()
                        .ok_or(ScriptError::UnbalancedConditional)?;
                    *last = !*last;
                }

                all::OP_ENDIF => {
                    if condition_stack.pop().is_none() {
                        return Err(ScriptError::UnbalancedConditional);
                    }
                }

                all::OP_VERIFY => {
                    let top = pop(stack)?;
                    if !cast_to_bool(&top) {
                        return Err(ScriptError::Verify);
                    }
                }

                all::OP_RETURN => return Err(ScriptError::OpReturn),

                // ------------------------------------------------- stack ops
                all::OP_TOALTSTACK => {
                    let top = pop(stack)?;
                    altstack.push(top);
                }
                all::OP_FROMALTSTACK => {
                    let top = altstack
                        .pop()
                        .ok_or(ScriptError::InvalidAltstackOperation)?;
                    stack.push(top);
                }
                all::OP_2DROP => {
                    require_depth(stack, 2)?;
                    stack.pop();
                    stack.pop();
                }
                all::OP_2DUP => {
                    require_depth(stack, 2)?;
                    let a = stack[stack.len() - 2].clone();
                    let b = stack[stack.len() - 1].clone();
                    stack.push(a);
                    stack.push(b);
                }
                all::OP_3DUP => {
                    require_depth(stack, 3)?;
                    let a = stack[stack.len() - 3].clone();
                    let b = stack[stack.len() - 2].clone();
                    let c = stack[stack.len() - 1].clone();
                    stack.push(a);
                    stack.push(b);
                    stack.push(c);
                }
                all::OP_2OVER => {
                    require_depth(stack, 4)?;
                    let a = stack[stack.len() - 4].clone();
                    let b = stack[stack.len() - 3].clone();
                    stack.push(a);
                    stack.push(b);
                }
                all::OP_2ROT => {
                    require_depth(stack, 6)?;
                    let len = stack.len();
                    let a = stack.remove(len - 6);
                    let b = stack.remove(len - 6);
                    stack.push(a);
                    stack.push(b);
                }
                all::OP_2SWAP => {
                    require_depth(stack, 4)?;
                    let len = stack.len();
                    stack.swap(len - 4, len - 2);
                    stack.swap(len - 3, len - 1);
                }
                all::OP_IFDUP => {
                    let top = stack_top(stack, 1)?.clone();
                    if cast_to_bool(&top) {
                        stack.push(top);
                    }
                }
                all::OP_DEPTH => {
                    stack.push(ScriptNum(stack.len() as i64).encode());
                }
                all::OP_DROP => {
                    pop(stack)?;
                }
                all::OP_DUP => {
                    let top = stack_top(stack, 1)?.clone();
                    stack.push(top);
                }
                all::OP_NIP => {
                    require_depth(stack, 2)?;
                    let len = stack.len();
                    stack.remove(len - 2);
                }
                all::OP_OVER => {
                    let item = stack_top(stack, 2)?.clone();
                    stack.push(item);
                }
                all::OP_PICK | all::OP_ROLL => {
                    require_depth(stack, 2)?;
                    let n = ScriptNum::decode(&pop(stack)?, require_minimal, DEFAULT_MAX_NUM_SIZE)?
                        .as_i64();
                    if n < 0 || n >= stack.len() as i64 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let index = stack.len() - 1 - n as usize;
                    if byte == all::OP_ROLL {
                        let item = stack.remove(index);
                        stack.push(item);
                    } else {
                        let item = stack[index].clone();
                        stack.push(item);
                    }
                }
                all::OP_ROT => {
                    require_depth(stack, 3)?;
                    let len = stack.len();
                    stack.swap(len - 3, len - 2);
                    stack.swap(len - 2, len - 1);
                }
                all::OP_SWAP => {
                    require_depth(stack, 2)?;
                    let len = stack.len();
                    stack.swap(len - 2, len - 1);
                }
                all::OP_TUCK => {
                    require_depth(stack, 2)?;
                    let top = stack[stack.len() - 1].clone();
                    stack.insert(stack.len() - 2, top);
                }
                all::OP_SIZE => {
                    let size = stack_top(stack, 1)?.len() as i64;
                    stack.push(ScriptNum(size).encode());
                }

                // ----------------------------------------------------- logic
                all::OP_EQUAL | all::OP_EQUALVERIFY => {
                    require_depth(stack, 2)?;
                    let b = pop(stack)?;
                    let a = pop(stack)?;
                    let equal = a == b;
                    if byte == all::OP_EQUALVERIFY {
                        if !equal {
                            return Err(ScriptError::EqualVerify);
                        }
                    } else {
                        stack.push(if equal { vec![1] } else { Vec::new() });
                    }
                }

                // ------------------------------------------------- unary num
                all::OP_1ADD
                | all::OP_1SUB
                | all::OP_NEGATE
                | all::OP_ABS
                | all::OP_NOT
                | all::OP_0NOTEQUAL => {
                    let value =
                        ScriptNum::decode(&pop(stack)?, require_minimal, DEFAULT_MAX_NUM_SIZE)?
                            .as_i64();
                    let result = match byte {
                        all::OP_1ADD => value + 1,
                        all::OP_1SUB => value - 1,
                        all::OP_NEGATE => -value,
                        all::OP_ABS => value.abs(),
                        all::OP_NOT => (value == 0) as i64,
                        _ => (value != 0) as i64,
                    };
                    stack.push(ScriptNum(result).encode());
                }

                // ------------------------------------------------ binary num
                all::OP_ADD
                | all::OP_SUB
                | all::OP_BOOLAND
                | all::OP_BOOLOR
                | all::OP_NUMEQUAL
                | all::OP_NUMEQUALVERIFY
                | all::OP_NUMNOTEQUAL
                | all::OP_LESSTHAN
                | all::OP_GREATERTHAN
                | all::OP_LESSTHANOREQUAL
                | all::OP_GREATERTHANOREQUAL
                | all::OP_MIN
                | all::OP_MAX => {
                    require_depth(stack, 2)?;
                    let b = ScriptNum::decode(&pop(stack)?, require_minimal, DEFAULT_MAX_NUM_SIZE)?
                        .as_i64();
                    let a = ScriptNum::decode(&pop(stack)?, require_minimal, DEFAULT_MAX_NUM_SIZE)?
                        .as_i64();
                    let result = match byte {
                        all::OP_ADD => a + b,
                        all::OP_SUB => a - b,
                        all::OP_BOOLAND => (a != 0 && b != 0) as i64,
                        all::OP_BOOLOR => (a != 0 || b != 0) as i64,
                        all::OP_NUMEQUAL | all::OP_NUMEQUALVERIFY => (a == b) as i64,
                        all::OP_NUMNOTEQUAL => (a != b) as i64,
                        all::OP_LESSTHAN => (a < b) as i64,
                        all::OP_GREATERTHAN => (a > b) as i64,
                        all::OP_LESSTHANOREQUAL => (a <= b) as i64,
                        all::OP_GREATERTHANOREQUAL => (a >= b) as i64,
                        all::OP_MIN => a.min(b),
                        _ => a.max(b),
                    };

                    if byte == all::OP_NUMEQUALVERIFY {
                        if result == 0 {
                            return Err(ScriptError::NumEqualVerify);
                        }
                    } else {
                        stack.push(ScriptNum(result).encode());
                    }
                }

                all::OP_WITHIN => {
                    require_depth(stack, 3)?;
                    let max =
                        ScriptNum::decode(&pop(stack)?, require_minimal, DEFAULT_MAX_NUM_SIZE)?
                            .as_i64();
                    let min =
                        ScriptNum::decode(&pop(stack)?, require_minimal, DEFAULT_MAX_NUM_SIZE)?
                            .as_i64();
                    let value =
                        ScriptNum::decode(&pop(stack)?, require_minimal, DEFAULT_MAX_NUM_SIZE)?
                            .as_i64();
                    stack.push(if min <= value && value < max {
                        vec![1]
                    } else {
                        Vec::new()
                    });
                }

                // ---------------------------------------------------- crypto
                all::OP_RIPEMD160
                | all::OP_SHA1
                | all::OP_SHA256
                | all::OP_HASH160
                | all::OP_HASH256 => {
                    let data = pop(stack)?;
                    let digest: Vec<u8> = match byte {
                        all::OP_RIPEMD160 => ripemd160(&data).to_vec(),
                        all::OP_SHA1 => sha1(&data).to_vec(),
                        all::OP_SHA256 => sha256(&data).to_vec(),
                        all::OP_HASH160 => hash160(&data).to_vec(),
                        _ => hash256(&data).to_vec(),
                    };
                    stack.push(digest);
                }

                all::OP_CODESEPARATOR => {
                    last_codeseparator = instruction.next;
                    // Tapscript signatures commit to the opcode position of the
                    // last executed OP_CODESEPARATOR.
                    exec_data.codeseparator_pos = instruction.offset as u32;
                }

                all::OP_CHECKSIG | all::OP_CHECKSIGVERIFY => {
                    require_depth(stack, 2)?;
                    let pubkey = pop(stack)?;
                    let sig = pop(stack)?;

                    let success = if sig_version == SigVersion::Tapscript {
                        eval_checksig_tapscript(&sig, &pubkey, flags, checker, exec_data)?
                    } else {
                        let script_code = build_script_code(
                            script,
                            last_codeseparator,
                            &sig,
                            sig_version,
                            flags,
                        )?;

                        check_signature_encoding(&sig, flags)?;
                        check_pubkey_encoding(
                            &pubkey,
                            flags,
                            sig_version == SigVersion::WitnessV0,
                        )?;

                        let ok = !sig.is_empty()
                            && checker.check_ecdsa_signature(
                                &sig,
                                &pubkey,
                                &script_code,
                                sig_version,
                            );

                        if !ok && flags.contains(VerifyFlags::NULLFAIL) && !sig.is_empty() {
                            return Err(ScriptError::SigNullFail);
                        }
                        ok
                    };

                    if byte == all::OP_CHECKSIGVERIFY {
                        if !success {
                            return Err(ScriptError::CheckSigVerify);
                        }
                    } else {
                        stack.push(if success { vec![1] } else { Vec::new() });
                    }
                }

                // BIP 342: replaces CHECKMULTISIG, which batches poorly with
                // schnorr. Stack effect is `(sig num pubkey -- num)`.
                OP_CHECKSIGADD => {
                    if sig_version != SigVersion::Tapscript {
                        return Err(ScriptError::BadOpcode);
                    }
                    require_depth(stack, 3)?;
                    let pubkey = pop(stack)?;
                    let num =
                        ScriptNum::decode(&pop(stack)?, require_minimal, DEFAULT_MAX_NUM_SIZE)?;
                    let sig = pop(stack)?;

                    let success =
                        eval_checksig_tapscript(&sig, &pubkey, flags, checker, exec_data)?;
                    stack.push(ScriptNum(num.as_i64() + i64::from(success)).encode());
                }

                all::OP_CHECKMULTISIG | all::OP_CHECKMULTISIGVERIFY => {
                    // BIP 342 removes batch verification entirely.
                    if sig_version == SigVersion::Tapscript {
                        return Err(ScriptError::TapscriptCheckMultisig);
                    }
                    let success = eval_checkmultisig(
                        stack,
                        script,
                        last_codeseparator,
                        flags,
                        checker,
                        sig_version,
                        &mut op_count,
                        require_minimal,
                    )?;

                    if byte == all::OP_CHECKMULTISIGVERIFY {
                        if !success {
                            return Err(ScriptError::CheckMultisigVerify);
                        }
                    } else {
                        stack.push(if success { vec![1] } else { Vec::new() });
                    }
                }

                _ => return Err(ScriptError::BadOpcode),
            }
        }

        if stack.len() + altstack.len() > MAX_STACK_SIZE {
            return Err(ScriptError::StackSize);
        }
    }

    if !condition_stack.is_empty() {
        return Err(ScriptError::UnbalancedConditional);
    }

    Ok(())
}

/// Build the scriptCode a signature commits to.
///
/// Bitcoin Core: the `scriptCode` construction inside `EvalScript`'s
/// `OP_CHECKSIG` branch — the script from the last `OP_CODESEPARATOR` onwards,
/// with the signature itself removed (pre-segwit only).
fn build_script_code(
    script: &[u8],
    last_codeseparator: usize,
    sig: &[u8],
    sig_version: SigVersion,
    flags: VerifyFlags,
) -> ScriptResult<Vec<u8>> {
    let mut script_code = script[last_codeseparator..].to_vec();

    if sig_version == SigVersion::Base {
        // A signature cannot commit to itself, so it is stripped from the
        // scriptCode. BIP 143 removed this step entirely.
        let mut sig_push = Vec::new();
        push_data(&mut sig_push, sig);
        let (cleaned, found) = find_and_delete(&script_code, &sig_push);

        if found > 0 && flags.contains(VerifyFlags::CONST_SCRIPTCODE) {
            return Err(ScriptError::SigFindAndDelete);
        }
        script_code = cleaned;

        if flags.contains(VerifyFlags::CONST_SCRIPTCODE) && contains_codeseparator(script) {
            return Err(ScriptError::OpCodeseparator);
        }
    }

    Ok(script_code)
}

/// Evaluate one tapscript signature check.
///
/// Bitcoin Core: `EvalChecksigTapscript()` in `src/script/interpreter.cpp`.
///
/// The ordering here is consensus critical, and deliberately unusual:
/// upgradable public key versions are handled *before* other rules; an empty
/// signature with an invalid public key still fails; and a non-empty invalid
/// signature aborts the script rather than pushing false. That last point is
/// taproot's built-in equivalent of `NULLFAIL`.
fn eval_checksig_tapscript(
    sig: &[u8],
    pubkey: &[u8],
    flags: VerifyFlags,
    checker: &dyn SignatureChecker,
    exec_data: &mut ScriptExecutionData,
) -> ScriptResult<bool> {
    let success = !sig.is_empty();

    if success {
        // BIP 342 sigops budget: every signature that gets as far as being
        // checked costs 50, including one under an upgradable key version.
        exec_data.validation_weight_left -= VALIDATION_WEIGHT_PER_SIGOP_PASSED;
        if exec_data.validation_weight_left < 0 {
            return Err(ScriptError::TapscriptValidationWeight);
        }
    }

    if pubkey.is_empty() {
        return Err(ScriptError::PubkeyType);
    } else if pubkey.len() == 32 {
        if success {
            checker.check_schnorr_signature(sig, pubkey, SigVersion::Tapscript, exec_data)?;
        }
    } else {
        // Any other length is a public key type a future soft fork may define.
        // Until then it verifies successfully, which is what makes the upgrade
        // possible without splitting the chain.
        if flags.contains(VerifyFlags::DISCOURAGE_UPGRADABLE_PUBKEYTYPE) {
            return Err(ScriptError::DiscourageUpgradablePubkeyType);
        }
    }

    Ok(success)
}

/// Bitcoin Core: the `OP_CHECKMULTISIG` branch of `EvalScript`.
#[allow(clippy::too_many_arguments)]
fn eval_checkmultisig(
    stack: &mut Stack,
    script: &[u8],
    last_codeseparator: usize,
    flags: VerifyFlags,
    checker: &dyn SignatureChecker,
    sig_version: SigVersion,
    op_count: &mut usize,
    require_minimal: bool,
) -> ScriptResult<bool> {
    let key_count =
        ScriptNum::decode(&pop(stack)?, require_minimal, DEFAULT_MAX_NUM_SIZE)?.as_i64();
    if !(0..=MAX_PUBKEYS_PER_MULTISIG).contains(&key_count) {
        return Err(ScriptError::PubkeyCount);
    }

    // Each key counts against the script's operation budget.
    *op_count += key_count as usize;
    if *op_count > MAX_OPS_PER_SCRIPT {
        return Err(ScriptError::OpCount);
    }

    require_depth(stack, key_count as usize)?;
    let mut pubkeys = Vec::with_capacity(key_count as usize);
    for _ in 0..key_count {
        pubkeys.push(pop(stack)?);
    }
    pubkeys.reverse();

    let sig_count =
        ScriptNum::decode(&pop(stack)?, require_minimal, DEFAULT_MAX_NUM_SIZE)?.as_i64();
    if sig_count < 0 || sig_count > key_count {
        return Err(ScriptError::SigCount);
    }

    require_depth(stack, sig_count as usize)?;
    let mut sigs = Vec::with_capacity(sig_count as usize);
    for _ in 0..sig_count {
        sigs.push(pop(stack)?);
    }
    sigs.reverse();

    // Core pops one element too many — a 2010 bug that is now consensus.
    // BIP 147 requires that element to be the empty push.
    let dummy = pop(stack)?;
    if flags.contains(VerifyFlags::NULLDUMMY) && !dummy.is_empty() {
        return Err(ScriptError::SigNullDummy);
    }

    let mut success = true;
    let mut sig_index = 0usize;
    let mut key_index = 0usize;
    let mut remaining_sigs = sigs.len();

    while remaining_sigs > 0 {
        let sig = &sigs[sig_index];
        let pubkey = &pubkeys[key_index];

        // Encoding is validated for every candidate pair, not just matches.
        check_signature_encoding(sig, flags)?;
        check_pubkey_encoding(pubkey, flags, sig_version == SigVersion::WitnessV0)?;

        let script_code = build_script_code(script, last_codeseparator, sig, sig_version, flags)?;
        let matched = !sig.is_empty()
            && checker.check_ecdsa_signature(sig, pubkey, &script_code, sig_version);

        if matched {
            sig_index += 1;
            remaining_sigs -= 1;
        }
        key_index += 1;

        // Not enough keys left to satisfy the remaining signatures.
        if remaining_sigs > pubkeys.len() - key_index {
            success = false;
            break;
        }
    }

    if !success && flags.contains(VerifyFlags::NULLFAIL) {
        // Every unmatched signature must have been the empty push.
        for sig in sigs.iter().skip(sig_index) {
            if !sig.is_empty() {
                return Err(ScriptError::SigNullFail);
            }
        }
    }

    Ok(success)
}

/// Verify an input's scripts.
///
/// Bitcoin Core: `VerifyScript()`.
pub fn verify_script(
    script_sig: &[u8],
    script_pubkey: &[u8],
    witness: &[Vec<u8>],
    flags: VerifyFlags,
    checker: &dyn SignatureChecker,
) -> ScriptResult<()> {
    // Witness data without WITNESS enabled would be unvalidated malleability.
    if !flags.contains(VerifyFlags::WITNESS) && !witness.is_empty() {
        return Err(ScriptError::WitnessUnexpected);
    }

    if flags.contains(VerifyFlags::SIGPUSHONLY) && !is_push_only(script_sig) {
        return Err(ScriptError::SigPushOnly);
    }

    let mut stack: Stack = Vec::new();
    eval_script(&mut stack, script_sig, flags, checker, SigVersion::Base)?;

    // P2SH needs the stack as it stood after scriptSig, before scriptPubKey.
    let stack_after_sig = stack.clone();

    eval_script(&mut stack, script_pubkey, flags, checker, SigVersion::Base)?;

    if stack.is_empty() || !cast_to_bool(stack.last().unwrap()) {
        return Err(ScriptError::EvalFalse);
    }

    let mut had_witness = false;

    // ------------------------------------------------------- native witness
    if flags.contains(VerifyFlags::WITNESS) {
        if let Some(program) = parse_witness_program(script_pubkey) {
            had_witness = true;
            // BIP 141: a witness program must be paid to directly, with an
            // empty scriptSig, or the txid would be malleable.
            if !script_sig.is_empty() {
                return Err(ScriptError::WitnessMalleated);
            }
            verify_witness_program(
                witness,
                program.version,
                &program.program,
                flags,
                checker,
                false,
            )?;
            // The witness program leaves exactly one true element.
            stack.truncate(1);
        }
    }

    // ------------------------------------------------------------ BIP16 P2SH
    if flags.contains(VerifyFlags::P2SH) && is_pay_to_script_hash(script_pubkey) {
        if !is_push_only(script_sig) {
            return Err(ScriptError::SigPushOnly);
        }

        // Core swaps in the post-scriptSig stack rather than returning early;
        // the CLEANSTACK and witness-unexpected checks below are shared with
        // the non-P2SH path and must run for both.
        stack = stack_after_sig;
        let redeem_script = stack.pop().ok_or(ScriptError::InvalidStackOperation)?;

        eval_script(&mut stack, &redeem_script, flags, checker, SigVersion::Base)?;

        if stack.is_empty() || !cast_to_bool(stack.last().unwrap()) {
            return Err(ScriptError::EvalFalse);
        }

        if flags.contains(VerifyFlags::WITNESS) {
            if let Some(program) = parse_witness_program(&redeem_script) {
                had_witness = true;
                // The scriptSig must be exactly the push of the redeemScript.
                let mut expected = Vec::new();
                push_data(&mut expected, &redeem_script);
                if script_sig != expected {
                    return Err(ScriptError::WitnessMalleatedP2sh);
                }
                verify_witness_program(
                    witness,
                    program.version,
                    &program.program,
                    flags,
                    checker,
                    true,
                )?;
                stack.truncate(1);
            }
        }
    }

    if flags.contains(VerifyFlags::CLEANSTACK) && stack.len() != 1 {
        return Err(ScriptError::CleanStack);
    }

    // A witness attached to a non-witness output is unvalidated data.
    if flags.contains(VerifyFlags::WITNESS) && !had_witness && !witness.is_empty() {
        return Err(ScriptError::WitnessUnexpected);
    }

    Ok(())
}

/// Bitcoin Core: `VerifyWitnessProgram()`.
fn verify_witness_program(
    witness: &[Vec<u8>],
    version: u8,
    program: &[u8],
    flags: VerifyFlags,
    checker: &dyn SignatureChecker,
    is_p2sh: bool,
) -> ScriptResult<()> {
    let mut exec_data = ScriptExecutionData::new();

    if version == 0 {
        let stack: Stack;
        let script: Vec<u8>;

        if program.len() == WITNESS_V0_SCRIPTHASH_SIZE {
            // P2WSH: the last witness item is the script, hashed with SHA256.
            if witness.is_empty() {
                return Err(ScriptError::WitnessProgramWitnessEmpty);
            }
            let (witness_script, rest) = witness.split_last().unwrap();
            if sha256(witness_script) != program {
                return Err(ScriptError::WitnessProgramMismatch);
            }
            script = witness_script.clone();
            stack = rest.to_vec();
        } else if program.len() == WITNESS_V0_KEYHASH_SIZE {
            // P2WPKH: exactly <signature> <pubkey>, and the implied script is
            // the standard P2PKH template over the program.
            if witness.len() != 2 {
                return Err(ScriptError::WitnessProgramMismatch);
            }
            let mut implied = vec![all::OP_DUP, all::OP_HASH160, 0x14];
            implied.extend_from_slice(program);
            implied.push(all::OP_EQUALVERIFY);
            implied.push(all::OP_CHECKSIG);
            script = implied;
            stack = witness.to_vec();
        } else {
            return Err(ScriptError::WitnessProgramWrongLength);
        }

        return execute_witness_script(
            stack,
            &script,
            flags,
            checker,
            SigVersion::WitnessV0,
            &mut exec_data,
        );
    }

    // ---------------------------------------------------------- BIP 341 v1
    // Taproot is deliberately not available under P2SH: wrapping it would
    // reintroduce the very malleability segwit removed.
    if version == 1
        && program.len() == WITNESS_V1_TAPROOT_SIZE
        && !is_p2sh
        && flags.contains(VerifyFlags::TAPROOT)
    {
        let mut stack: Stack = witness.to_vec();

        if stack.is_empty() {
            return Err(ScriptError::WitnessProgramWitnessEmpty);
        }

        // A trailing item tagged 0x50 is the annex: reserved for future use,
        // committed to by the signature, but otherwise not interpreted.
        if stack.len() >= 2 {
            if let Some(last) = stack.last() {
                if last.first() == Some(&ANNEX_TAG) {
                    let annex = stack.pop().unwrap();
                    let mut serialized = Vec::with_capacity(annex.len() + 9);
                    write_compact_size(&mut serialized, annex.len() as u64);
                    serialized.extend_from_slice(&annex);
                    exec_data.annex_hash = Some(sha256(&serialized));
                }
            }
        }
        if stack.len() == 1 {
            // Key path: the sole item is a signature over the output key.
            checker.check_schnorr_signature(&stack[0], program, SigVersion::Taproot, &exec_data)?;
            return Ok(());
        }

        // Script path: <inputs...> <script> <control block>
        let control = stack.pop().unwrap();
        let script = stack.pop().unwrap();

        let Some(control) = parse_control_block(&control) else {
            return Err(ScriptError::TaprootWrongControlSize);
        };

        let tapleaf_hash = compute_tapleaf_hash(control.leaf_version, &script);
        if !verify_taproot_commitment(secp256k1::SECP256K1, &control, program, tapleaf_hash) {
            return Err(ScriptError::WitnessProgramMismatch);
        }
        exec_data.tapleaf_hash = Some(tapleaf_hash);

        if control.leaf_version & TAPROOT_LEAF_MASK == TAPROOT_LEAF_TAPSCRIPT {
            // The sigops budget scales with how much the spender paid for:
            // 50 units of slack plus the serialised witness size, minus 50 per
            // signature actually checked.
            exec_data.validation_weight_left =
                serialized_witness_size(witness) as i64 + VALIDATION_WEIGHT_OFFSET;

            return execute_witness_script(
                stack,
                &script,
                flags,
                checker,
                SigVersion::Tapscript,
                &mut exec_data,
            );
        }

        // A leaf version other than 0xc0 is reserved for future soft forks and
        // is unencumbered until one defines it.
        if flags.contains(VerifyFlags::DISCOURAGE_UPGRADABLE_TAPROOT_VERSION) {
            return Err(ScriptError::DiscourageUpgradableTaprootVersion);
        }
        return Ok(());
    }

    if flags.contains(VerifyFlags::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM) {
        return Err(ScriptError::DiscourageUpgradableWitnessProgram);
    }

    // Unknown witness version: anyone-can-spend for this node, which is exactly
    // how a node predating the version in question behaves.
    Ok(())
}

/// Run a witness script and apply the rules common to every witness version.
///
/// Bitcoin Core: `ExecuteWitnessScript()`.
fn execute_witness_script(
    mut stack: Stack,
    script: &[u8],
    flags: VerifyFlags,
    checker: &dyn SignatureChecker,
    sig_version: SigVersion,
    exec_data: &mut ScriptExecutionData,
) -> ScriptResult<()> {
    if sig_version == SigVersion::Tapscript {
        // OP_SUCCESSx overrides everything — including the checks below — so it
        // is scanned for before anything else runs.
        for instruction in Instructions::new(script) {
            let instruction = instruction?;
            if is_op_success(instruction.opcode.to_u8()) {
                if flags.contains(VerifyFlags::DISCOURAGE_OP_SUCCESS) {
                    return Err(ScriptError::DiscourageOpSuccess);
                }
                return Ok(());
            }
        }

        // Tapscript enforces the stack limit on the initial witness stack; the
        // altstack is necessarily empty at this point.
        if stack.len() > MAX_STACK_SIZE {
            return Err(ScriptError::StackSize);
        }
    }

    for element in &stack {
        if element.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(ScriptError::PushSize);
        }
    }

    eval_script_with_data(&mut stack, script, flags, checker, sig_version, exec_data)?;

    // Witness scripts are always clean-stack.
    if stack.len() != 1 {
        return Err(ScriptError::CleanStack);
    }
    if !cast_to_bool(&stack[0]) {
        return Err(ScriptError::EvalFalse);
    }

    Ok(())
}

/// Serialised size of a witness stack, as the sigops budget counts it.
///
/// Bitcoin Core: `GetSerializeSize(witness.stack)`.
fn serialized_witness_size(witness: &[Vec<u8>]) -> usize {
    let mut size = Vec::new();
    write_compact_size(&mut size, witness.len() as u64);
    let mut total = size.len();
    for item in witness {
        let mut prefix = Vec::new();
        write_compact_size(&mut prefix, item.len() as u64);
        total += prefix.len() + item.len();
    }
    total
}

// ---------------------------------------------------------------------------
// Stack helpers
// ---------------------------------------------------------------------------

fn pop(stack: &mut Stack) -> ScriptResult<Vec<u8>> {
    stack.pop().ok_or(ScriptError::InvalidStackOperation)
}

fn require_depth(stack: &Stack, depth: usize) -> ScriptResult<()> {
    if stack.len() < depth {
        return Err(ScriptError::InvalidStackOperation);
    }
    Ok(())
}

/// `depth`-th element from the top (1 = top).
fn stack_top(stack: &Stack, depth: usize) -> ScriptResult<&Vec<u8>> {
    if stack.len() < depth {
        return Err(ScriptError::InvalidStackOperation);
    }
    Ok(&stack[stack.len() - depth])
}
