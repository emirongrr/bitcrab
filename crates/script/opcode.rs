//! Bitcoin Script opcodes.
//!
//! Mirrors `opcodetype` in Bitcoin Core `src/script/script.h`.
//!
//! Represented as a newtype over `u8` rather than a Rust enum: the opcode space
//! is fully populated (every one of the 256 bytes is a valid opcode, most of
//! them `OP_INVALIDOPCODE`), so an enum would either need 256 variants or an
//! unsound `transmute` on the byte.

/// A single opcode byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Opcode(pub u8);

/// Raw opcode byte constants, named as in Bitcoin Core.
#[allow(dead_code)]
pub mod all {
    // Push value
    pub const OP_0: u8 = 0x00;
    pub const OP_FALSE: u8 = OP_0;
    pub const OP_PUSHDATA1: u8 = 0x4c;
    pub const OP_PUSHDATA2: u8 = 0x4d;
    pub const OP_PUSHDATA4: u8 = 0x4e;
    pub const OP_1NEGATE: u8 = 0x4f;
    pub const OP_RESERVED: u8 = 0x50;
    pub const OP_1: u8 = 0x51;
    pub const OP_TRUE: u8 = OP_1;
    pub const OP_2: u8 = 0x52;
    pub const OP_3: u8 = 0x53;
    pub const OP_4: u8 = 0x54;
    pub const OP_5: u8 = 0x55;
    pub const OP_6: u8 = 0x56;
    pub const OP_7: u8 = 0x57;
    pub const OP_8: u8 = 0x58;
    pub const OP_9: u8 = 0x59;
    pub const OP_10: u8 = 0x5a;
    pub const OP_11: u8 = 0x5b;
    pub const OP_12: u8 = 0x5c;
    pub const OP_13: u8 = 0x5d;
    pub const OP_14: u8 = 0x5e;
    pub const OP_15: u8 = 0x5f;
    pub const OP_16: u8 = 0x60;

    // Control
    pub const OP_NOP: u8 = 0x61;
    pub const OP_VER: u8 = 0x62;
    pub const OP_IF: u8 = 0x63;
    pub const OP_NOTIF: u8 = 0x64;
    pub const OP_VERIF: u8 = 0x65;
    pub const OP_VERNOTIF: u8 = 0x66;
    pub const OP_ELSE: u8 = 0x67;
    pub const OP_ENDIF: u8 = 0x68;
    pub const OP_VERIFY: u8 = 0x69;
    pub const OP_RETURN: u8 = 0x6a;

    // Stack ops
    pub const OP_TOALTSTACK: u8 = 0x6b;
    pub const OP_FROMALTSTACK: u8 = 0x6c;
    pub const OP_2DROP: u8 = 0x6d;
    pub const OP_2DUP: u8 = 0x6e;
    pub const OP_3DUP: u8 = 0x6f;
    pub const OP_2OVER: u8 = 0x70;
    pub const OP_2ROT: u8 = 0x71;
    pub const OP_2SWAP: u8 = 0x72;
    pub const OP_IFDUP: u8 = 0x73;
    pub const OP_DEPTH: u8 = 0x74;
    pub const OP_DROP: u8 = 0x75;
    pub const OP_DUP: u8 = 0x76;
    pub const OP_NIP: u8 = 0x77;
    pub const OP_OVER: u8 = 0x78;
    pub const OP_PICK: u8 = 0x79;
    pub const OP_ROLL: u8 = 0x7a;
    pub const OP_ROT: u8 = 0x7b;
    pub const OP_SWAP: u8 = 0x7c;
    pub const OP_TUCK: u8 = 0x7d;

    // Splice ops (disabled)
    pub const OP_CAT: u8 = 0x7e;
    pub const OP_SUBSTR: u8 = 0x7f;
    pub const OP_LEFT: u8 = 0x80;
    pub const OP_RIGHT: u8 = 0x81;
    pub const OP_SIZE: u8 = 0x82;

    // Bit logic
    pub const OP_INVERT: u8 = 0x83; // disabled
    pub const OP_AND: u8 = 0x84; // disabled
    pub const OP_OR: u8 = 0x85; // disabled
    pub const OP_XOR: u8 = 0x86; // disabled
    pub const OP_EQUAL: u8 = 0x87;
    pub const OP_EQUALVERIFY: u8 = 0x88;
    pub const OP_RESERVED1: u8 = 0x89;
    pub const OP_RESERVED2: u8 = 0x8a;

    // Numeric
    pub const OP_1ADD: u8 = 0x8b;
    pub const OP_1SUB: u8 = 0x8c;
    pub const OP_2MUL: u8 = 0x8d; // disabled
    pub const OP_2DIV: u8 = 0x8e; // disabled
    pub const OP_NEGATE: u8 = 0x8f;
    pub const OP_ABS: u8 = 0x90;
    pub const OP_NOT: u8 = 0x91;
    pub const OP_0NOTEQUAL: u8 = 0x92;
    pub const OP_ADD: u8 = 0x93;
    pub const OP_SUB: u8 = 0x94;
    pub const OP_MUL: u8 = 0x95; // disabled
    pub const OP_DIV: u8 = 0x96; // disabled
    pub const OP_MOD: u8 = 0x97; // disabled
    pub const OP_LSHIFT: u8 = 0x98; // disabled
    pub const OP_RSHIFT: u8 = 0x99; // disabled
    pub const OP_BOOLAND: u8 = 0x9a;
    pub const OP_BOOLOR: u8 = 0x9b;
    pub const OP_NUMEQUAL: u8 = 0x9c;
    pub const OP_NUMEQUALVERIFY: u8 = 0x9d;
    pub const OP_NUMNOTEQUAL: u8 = 0x9e;
    pub const OP_LESSTHAN: u8 = 0x9f;
    pub const OP_GREATERTHAN: u8 = 0xa0;
    pub const OP_LESSTHANOREQUAL: u8 = 0xa1;
    pub const OP_GREATERTHANOREQUAL: u8 = 0xa2;
    pub const OP_MIN: u8 = 0xa3;
    pub const OP_MAX: u8 = 0xa4;
    pub const OP_WITHIN: u8 = 0xa5;

    // Crypto
    pub const OP_RIPEMD160: u8 = 0xa6;
    pub const OP_SHA1: u8 = 0xa7;
    pub const OP_SHA256: u8 = 0xa8;
    pub const OP_HASH160: u8 = 0xa9;
    pub const OP_HASH256: u8 = 0xaa;
    pub const OP_CODESEPARATOR: u8 = 0xab;
    pub const OP_CHECKSIG: u8 = 0xac;
    pub const OP_CHECKSIGVERIFY: u8 = 0xad;
    pub const OP_CHECKMULTISIG: u8 = 0xae;
    pub const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;

    // Expansion
    pub const OP_NOP1: u8 = 0xb0;
    pub const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;
    pub const OP_NOP2: u8 = OP_CHECKLOCKTIMEVERIFY;
    pub const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2;
    pub const OP_NOP3: u8 = OP_CHECKSEQUENCEVERIFY;
    pub const OP_NOP4: u8 = 0xb3;
    pub const OP_NOP5: u8 = 0xb4;
    pub const OP_NOP6: u8 = 0xb5;
    pub const OP_NOP7: u8 = 0xb6;
    pub const OP_NOP8: u8 = 0xb7;
    pub const OP_NOP9: u8 = 0xb8;
    pub const OP_NOP10: u8 = 0xb9;

    pub const OP_INVALIDOPCODE: u8 = 0xff;
}

impl Opcode {
    pub const fn to_u8(self) -> u8 {
        self.0
    }

    /// True if this opcode pushes data (`<= OP_16`).
    ///
    /// Bitcoin Core: the `opcode > OP_16` test in `CScript::IsPushOnly()`.
    pub const fn is_push(self) -> bool {
        self.0 <= all::OP_16
    }

    /// True if the opcode counts towards `MAX_OPS_PER_SCRIPT`.
    ///
    /// Bitcoin Core: `if (opcode > OP_16 && ++nOpCount > MAX_OPS_PER_SCRIPT)`.
    pub const fn counts_towards_op_limit(self) -> bool {
        self.0 > all::OP_16
    }

    /// True for opcodes disabled in 2010 and permanently invalid since —
    /// they fail the script even inside an unexecuted IF branch.
    ///
    /// Bitcoin Core: the `IsOpcodeDisabled()` check placed *before* the
    /// `fExec` branch in `EvalScript`.
    pub const fn is_disabled(self) -> bool {
        matches!(
            self.0,
            all::OP_CAT
                | all::OP_SUBSTR
                | all::OP_LEFT
                | all::OP_RIGHT
                | all::OP_INVERT
                | all::OP_AND
                | all::OP_OR
                | all::OP_XOR
                | all::OP_2MUL
                | all::OP_2DIV
                | all::OP_MUL
                | all::OP_DIV
                | all::OP_MOD
                | all::OP_LSHIFT
                | all::OP_RSHIFT
        )
    }

    /// Value pushed by `OP_1`..`OP_16` / `OP_1NEGATE`.
    ///
    /// Bitcoin Core: `CScript::DecodeOP_N()`.
    pub const fn decode_op_n(self) -> Option<i64> {
        match self.0 {
            all::OP_0 => Some(0),
            all::OP_1NEGATE => Some(-1),
            n if n >= all::OP_1 && n <= all::OP_16 => Some((n - (all::OP_1 - 1)) as i64),
            _ => None,
        }
    }

    pub fn name(self) -> String {
        let byte = self.0;
        let named = match byte {
            all::OP_0 => "OP_0",
            0x01..=0x4b => return format!("OP_PUSHBYTES_{}", byte),
            all::OP_PUSHDATA1 => "OP_PUSHDATA1",
            all::OP_PUSHDATA2 => "OP_PUSHDATA2",
            all::OP_PUSHDATA4 => "OP_PUSHDATA4",
            all::OP_1NEGATE => "OP_1NEGATE",
            all::OP_RESERVED => "OP_RESERVED",
            0x51..=0x60 => return format!("OP_{}", byte - 0x50),
            all::OP_NOP => "OP_NOP",
            all::OP_IF => "OP_IF",
            all::OP_NOTIF => "OP_NOTIF",
            all::OP_ELSE => "OP_ELSE",
            all::OP_ENDIF => "OP_ENDIF",
            all::OP_VERIFY => "OP_VERIFY",
            all::OP_RETURN => "OP_RETURN",
            all::OP_TOALTSTACK => "OP_TOALTSTACK",
            all::OP_FROMALTSTACK => "OP_FROMALTSTACK",
            all::OP_DROP => "OP_DROP",
            all::OP_DUP => "OP_DUP",
            all::OP_SIZE => "OP_SIZE",
            all::OP_EQUAL => "OP_EQUAL",
            all::OP_EQUALVERIFY => "OP_EQUALVERIFY",
            all::OP_ADD => "OP_ADD",
            all::OP_SUB => "OP_SUB",
            all::OP_RIPEMD160 => "OP_RIPEMD160",
            all::OP_SHA1 => "OP_SHA1",
            all::OP_SHA256 => "OP_SHA256",
            all::OP_HASH160 => "OP_HASH160",
            all::OP_HASH256 => "OP_HASH256",
            all::OP_CODESEPARATOR => "OP_CODESEPARATOR",
            all::OP_CHECKSIG => "OP_CHECKSIG",
            all::OP_CHECKSIGVERIFY => "OP_CHECKSIGVERIFY",
            all::OP_CHECKMULTISIG => "OP_CHECKMULTISIG",
            all::OP_CHECKMULTISIGVERIFY => "OP_CHECKMULTISIGVERIFY",
            all::OP_CHECKLOCKTIMEVERIFY => "OP_CHECKLOCKTIMEVERIFY",
            all::OP_CHECKSEQUENCEVERIFY => "OP_CHECKSEQUENCEVERIFY",
            _ => return format!("OP_UNKNOWN_{:#04x}", byte),
        };
        named.to_string()
    }
}

impl From<u8> for Opcode {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for Opcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_byte_converts_without_undefined_behaviour() {
        // The previous implementation transmuted arbitrary bytes into a sparse
        // enum. Exercising the whole space guards against a regression.
        for byte in 0u8..=255 {
            let op = Opcode::from(byte);
            assert_eq!(op.to_u8(), byte);
            assert!(!op.name().is_empty());
        }
    }

    #[test]
    fn op_n_decoding_matches_core() {
        assert_eq!(Opcode(all::OP_0).decode_op_n(), Some(0));
        assert_eq!(Opcode(all::OP_1NEGATE).decode_op_n(), Some(-1));
        assert_eq!(Opcode(all::OP_1).decode_op_n(), Some(1));
        assert_eq!(Opcode(all::OP_16).decode_op_n(), Some(16));
        assert_eq!(Opcode(all::OP_DUP).decode_op_n(), None);
    }

    #[test]
    fn push_boundary_is_op_16() {
        assert!(Opcode(all::OP_16).is_push());
        assert!(!Opcode(all::OP_NOP).is_push());
        assert!(!Opcode(all::OP_16).counts_towards_op_limit());
        assert!(Opcode(all::OP_NOP).counts_towards_op_limit());
    }

    #[test]
    fn the_2010_disabled_opcodes_are_flagged() {
        for byte in [
            all::OP_CAT,
            all::OP_SUBSTR,
            all::OP_LEFT,
            all::OP_RIGHT,
            all::OP_INVERT,
            all::OP_AND,
            all::OP_OR,
            all::OP_XOR,
            all::OP_2MUL,
            all::OP_2DIV,
            all::OP_MUL,
            all::OP_DIV,
            all::OP_MOD,
            all::OP_LSHIFT,
            all::OP_RSHIFT,
        ] {
            assert!(Opcode(byte).is_disabled(), "{:#04x} must be disabled", byte);
        }
        // OP_SIZE sits in the middle of the splice range but was never disabled.
        assert!(!Opcode(all::OP_SIZE).is_disabled());
        assert!(!Opcode(all::OP_EQUAL).is_disabled());
    }
}
