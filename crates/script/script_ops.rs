//! Script parsing and structural predicates.
//!
//! Bitcoin Core: `CScript::GetOp()`, `IsPushOnly()`, `IsPayToScriptHash()`,
//! `IsWitnessProgram()` and `FindAndDelete()` in `src/script/script.cpp`.

use crate::error::{ScriptError, ScriptResult};
use crate::opcode::{all, Opcode};

/// One decoded step of a script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction<'a> {
    /// Byte offset of the opcode within the script.
    pub offset: usize,
    pub opcode: Opcode,
    /// Payload for push opcodes; empty for everything else.
    pub data: &'a [u8],
    /// Offset just past this instruction.
    pub next: usize,
}

/// Iterate a script the way `CScript::GetOp` does.
///
/// A truncated push is a hard error (`BadOpcode`), matching Core's `GetOp`
/// returning false.
pub struct Instructions<'a> {
    script: &'a [u8],
    pos: usize,
}

impl<'a> Instructions<'a> {
    pub fn new(script: &'a [u8]) -> Self {
        Self { script, pos: 0 }
    }
}

impl<'a> Iterator for Instructions<'a> {
    type Item = ScriptResult<Instruction<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.script.len() {
            return None;
        }

        let offset = self.pos;
        let opcode_byte = self.script[self.pos];
        let mut cursor = self.pos + 1;

        let mut len = 0usize;
        if opcode_byte <= all::OP_PUSHDATA4 {
            if opcode_byte < all::OP_PUSHDATA1 {
                len = opcode_byte as usize;
            } else {
                let size_len = match opcode_byte {
                    all::OP_PUSHDATA1 => 1,
                    all::OP_PUSHDATA2 => 2,
                    _ => 4,
                };
                if self.script.len() - cursor < size_len {
                    self.pos = self.script.len();
                    return Some(Err(ScriptError::BadOpcode));
                }
                len = match size_len {
                    1 => self.script[cursor] as usize,
                    2 => u16::from_le_bytes(self.script[cursor..cursor + 2].try_into().unwrap())
                        as usize,
                    _ => u32::from_le_bytes(self.script[cursor..cursor + 4].try_into().unwrap())
                        as usize,
                };
                cursor += size_len;
            }

            if self.script.len() - cursor < len {
                self.pos = self.script.len();
                return Some(Err(ScriptError::BadOpcode));
            }
        }

        let data = &self.script[cursor..cursor + len];
        self.pos = cursor + len;

        Some(Ok(Instruction {
            offset,
            opcode: Opcode(opcode_byte),
            data,
            next: self.pos,
        }))
    }
}

/// True if the script consists only of push operations.
///
/// Bitcoin Core: `CScript::IsPushOnly()`. A malformed push makes it false.
pub fn is_push_only(script: &[u8]) -> bool {
    for instruction in Instructions::new(script) {
        match instruction {
            Ok(instruction) if instruction.opcode.is_push() => {}
            _ => return false,
        }
    }
    true
}

/// True if `script` matches the BIP 16 pattern `OP_HASH160 <20 bytes> OP_EQUAL`.
///
/// Bitcoin Core: `CScript::IsPayToScriptHash()`. This is a byte-pattern test,
/// deliberately not a parse — a script that merely *evaluates* the same way is
/// not P2SH.
pub fn is_pay_to_script_hash(script: &[u8]) -> bool {
    script.len() == 23
        && script[0] == all::OP_HASH160
        && script[1] == 0x14
        && script[22] == all::OP_EQUAL
}

/// A parsed BIP 141 witness program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessProgram {
    pub version: u8,
    pub program: Vec<u8>,
}

/// Parse `script` as a witness program.
///
/// Bitcoin Core: `CScript::IsWitnessProgram()` — `OP_0`/`OP_1`..`OP_16`
/// followed by a single 2..40 byte push that spans the rest of the script.
pub fn parse_witness_program(script: &[u8]) -> Option<WitnessProgram> {
    if script.len() < 4 || script.len() > 42 {
        return None;
    }
    let version_byte = script[0];
    if version_byte != all::OP_0 && !(all::OP_1..=all::OP_16).contains(&version_byte) {
        return None;
    }
    // The push opcode must account for exactly the remaining bytes.
    if script[1] as usize + 2 != script.len() {
        return None;
    }

    let version = if version_byte == all::OP_0 {
        0
    } else {
        version_byte - (all::OP_1 - 1)
    };

    Some(WitnessProgram {
        version,
        program: script[2..].to_vec(),
    })
}

/// Remove every occurrence of the push of `signature` from `script`.
///
/// Bitcoin Core: `FindAndDelete()` in `src/script/interpreter.cpp`. This exists
/// only for pre-segwit signature hashing, where the signature being checked has
/// to be stripped out of the scriptCode it appears in. Matching is done on
/// opcode boundaries, so a coincidental byte sequence inside another push is
/// not removed.
pub fn find_and_delete(script: &[u8], signature_push: &[u8]) -> (Vec<u8>, usize) {
    if signature_push.is_empty() || script.len() < signature_push.len() {
        return (script.to_vec(), 0);
    }

    let mut result = Vec::with_capacity(script.len());
    let mut found = 0usize;
    let mut last_kept = 0usize;
    let mut pos = 0usize;

    // Walk instruction boundaries; only a match that starts exactly on one
    // counts, which is what makes this safe against embedded byte sequences.
    while pos + signature_push.len() <= script.len() {
        if &script[pos..pos + signature_push.len()] == signature_push {
            result.extend_from_slice(&script[last_kept..pos]);
            pos += signature_push.len();
            last_kept = pos;
            found += 1;
            continue;
        }

        let mut iter = Instructions::new(&script[pos..]);
        match iter.next() {
            Some(Ok(instruction)) => pos += instruction.next,
            _ => break,
        }
    }

    result.extend_from_slice(&script[last_kept..]);
    (result, found)
}

/// True if `script` contains an `OP_CODESEPARATOR` at an instruction boundary.
///
/// Bitcoin Core: the `SCRIPT_VERIFY_CONST_SCRIPTCODE` check in `EvalScript`.
pub fn contains_codeseparator(script: &[u8]) -> bool {
    Instructions::new(script).any(
        |instruction| matches!(instruction, Ok(i) if i.opcode.to_u8() == all::OP_CODESEPARATOR),
    )
}

/// Encode a minimal data push of `data`.
///
/// Bitcoin Core: `CScript::operator<<(const std::vector<unsigned char>&)`.
pub fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    match data.len() {
        len if len < all::OP_PUSHDATA1 as usize => script.push(len as u8),
        len if len <= 0xff => {
            script.push(all::OP_PUSHDATA1);
            script.push(len as u8);
        }
        len if len <= 0xffff => {
            script.push(all::OP_PUSHDATA2);
            script.extend_from_slice(&(len as u16).to_le_bytes());
        }
        len => {
            script.push(all::OP_PUSHDATA4);
            script.extend_from_slice(&(len as u32).to_le_bytes());
        }
    }
    script.extend_from_slice(data);
}

/// True if `data` was pushed with the shortest available opcode.
///
/// Bitcoin Core: `CheckMinimalPush()` in `src/script/interpreter.cpp`.
pub fn check_minimal_push(data: &[u8], opcode: Opcode) -> bool {
    let op = opcode.to_u8();

    if data.is_empty() {
        // Should have used OP_0.
        return op == all::OP_0;
    }
    if data.len() == 1 && (1..=16).contains(&data[0]) {
        // Should have used OP_1 .. OP_16.
        return op == all::OP_1 + data[0] - 1;
    }
    if data.len() == 1 && data[0] == 0x81 {
        // Should have used OP_1NEGATE.
        return op == all::OP_1NEGATE;
    }
    if data.len() <= 75 {
        // Should have used a direct push.
        return op as usize == data.len();
    }
    if data.len() <= 255 {
        return op == all::OP_PUSHDATA1;
    }
    if data.len() <= 65535 {
        return op == all::OP_PUSHDATA2;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ops(script: &[u8]) -> Vec<u8> {
        Instructions::new(script)
            .map(|i| i.unwrap().opcode.to_u8())
            .collect()
    }

    #[test]
    fn parses_direct_pushes_and_opcodes() {
        // <0x01 0x02> OP_DUP OP_HASH160
        let script = vec![0x02, 0x01, 0x02, all::OP_DUP, all::OP_HASH160];
        assert_eq!(ops(&script), vec![0x02, all::OP_DUP, all::OP_HASH160]);

        let first = Instructions::new(&script).next().unwrap().unwrap();
        assert_eq!(first.data, &[0x01, 0x02]);
        assert_eq!(first.next, 3);
    }

    #[test]
    fn parses_all_three_pushdata_widths() {
        let mut script = Vec::new();
        push_data(&mut script, &[0xaa; 80]); // PUSHDATA1
        push_data(&mut script, &[0xbb; 300]); // PUSHDATA2
        let parsed: Vec<_> = Instructions::new(&script).map(|i| i.unwrap()).collect();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].opcode.to_u8(), all::OP_PUSHDATA1);
        assert_eq!(parsed[0].data.len(), 80);
        assert_eq!(parsed[1].opcode.to_u8(), all::OP_PUSHDATA2);
        assert_eq!(parsed[1].data.len(), 300);
    }

    #[test]
    fn truncated_push_is_an_error_not_a_panic() {
        // Claims 5 bytes but only 2 follow.
        let script = vec![0x05, 0x01, 0x02];
        let results: Vec<_> = Instructions::new(&script).collect();
        assert_eq!(results, vec![Err(ScriptError::BadOpcode)]);

        // PUSHDATA2 with a truncated length field.
        let script = vec![all::OP_PUSHDATA2, 0x01];
        let results: Vec<_> = Instructions::new(&script).collect();
        assert_eq!(results, vec![Err(ScriptError::BadOpcode)]);
    }

    #[test]
    fn push_only_rejects_non_pushes_and_malformed_scripts() {
        assert!(is_push_only(&[0x02, 0x01, 0x02, all::OP_1]));
        assert!(is_push_only(&[]));
        assert!(!is_push_only(&[all::OP_DUP]));
        assert!(
            !is_push_only(&[0x05, 0x01]),
            "truncated push is not push-only"
        );
    }

    #[test]
    fn recognises_p2sh_by_exact_pattern() {
        let mut script = vec![all::OP_HASH160, 0x14];
        script.extend_from_slice(&[0x11; 20]);
        script.push(all::OP_EQUAL);
        assert!(is_pay_to_script_hash(&script));

        // One byte longer: not P2SH, even though it starts the same.
        let mut longer = script.clone();
        longer.push(all::OP_NOP);
        assert!(!is_pay_to_script_hash(&longer));
    }

    #[test]
    fn parses_witness_programs() {
        let mut p2wpkh = vec![all::OP_0, 0x14];
        p2wpkh.extend_from_slice(&[0x22; 20]);
        let parsed = parse_witness_program(&p2wpkh).unwrap();
        assert_eq!(parsed.version, 0);
        assert_eq!(parsed.program.len(), 20);

        let mut p2tr = vec![all::OP_1, 0x20];
        p2tr.extend_from_slice(&[0x33; 32]);
        let parsed = parse_witness_program(&p2tr).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.program.len(), 32);

        // Trailing junk means it is not a witness program.
        let mut malformed = p2wpkh.clone();
        malformed.push(all::OP_NOP);
        assert_eq!(parse_witness_program(&malformed), None);
        assert_eq!(parse_witness_program(&[all::OP_0, 0x01, 0xff]), None);
    }

    #[test]
    fn find_and_delete_removes_whole_pushes_only() {
        let mut sig_push = Vec::new();
        push_data(&mut sig_push, &[0xde, 0xad]);

        let mut script = Vec::new();
        push_data(&mut script, &[0xde, 0xad]);
        script.push(all::OP_DUP);
        push_data(&mut script, &[0xde, 0xad]);

        let (cleaned, count) = find_and_delete(&script, &sig_push);
        assert_eq!(count, 2);
        assert_eq!(cleaned, vec![all::OP_DUP]);
    }

    #[test]
    fn find_and_delete_leaves_unrelated_scripts_alone() {
        let mut sig_push = Vec::new();
        push_data(&mut sig_push, &[0xde, 0xad]);
        let script = vec![all::OP_DUP, all::OP_HASH160];
        let (cleaned, count) = find_and_delete(&script, &sig_push);
        assert_eq!(count, 0);
        assert_eq!(cleaned, script);
    }

    #[test]
    fn minimal_push_rules_match_core() {
        assert!(check_minimal_push(&[], Opcode(all::OP_0)));
        assert!(!check_minimal_push(&[], Opcode(0x01)));

        assert!(check_minimal_push(&[5], Opcode(all::OP_1 + 4)));
        assert!(!check_minimal_push(&[5], Opcode(0x01)));

        assert!(check_minimal_push(&[0x81], Opcode(all::OP_1NEGATE)));
        assert!(!check_minimal_push(&[0x81], Opcode(0x01)));

        // 0x00 is not OP_0-encodable as a one-byte push value.
        assert!(check_minimal_push(&[0x00], Opcode(0x01)));

        assert!(check_minimal_push(&[0xaa; 80], Opcode(all::OP_PUSHDATA1)));
        assert!(!check_minimal_push(&[0xaa; 80], Opcode(all::OP_PUSHDATA2)));
    }

    #[test]
    fn detects_codeseparator_at_instruction_boundaries() {
        assert!(contains_codeseparator(&[
            all::OP_DUP,
            all::OP_CODESEPARATOR
        ]));
        // The same byte inside a push payload is data, not an opcode.
        let mut script = Vec::new();
        push_data(&mut script, &[all::OP_CODESEPARATOR]);
        assert!(!contains_codeseparator(&script));
    }
}
