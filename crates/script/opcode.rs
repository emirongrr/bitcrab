//! Bitcoin Script Opcodes.
//!
//! Matches `opcodetype` in Bitcoin Core `src/script/script.h`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum Opcode {
    // Push data
    OP_0 = 0x00,
    OP_PUSHBYTES_1 = 0x01,
    // ... op_pushbytes 2..75
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE = 0x4f,
    OP_RESERVED = 0x50,
    OP_1 = 0x51,
    OP_2 = 0x52,
    OP_3 = 0x53,
    OP_4 = 0x54,
    OP_5 = 0x55,
    OP_6 = 0x56,
    OP_7 = 0x57,
    OP_8 = 0x58,
    OP_9 = 0x59,
    OP_10 = 0x5a,
    OP_11 = 0x5b,
    OP_12 = 0x5c,
    OP_13 = 0x5d,
    OP_14 = 0x5e,
    OP_15 = 0x5f,
    OP_16 = 0x60,

    // Control
    OP_NOP = 0x61,
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6a,

    // Stack ops
    OP_DUP = 0x76,
    OP_DROP = 0x75,
    OP_SWAP = 0x7c,

    // Bitwise/Logic
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,

    // Arithmetic
    OP_ADD = 0x93,
    OP_SUB = 0x94,

    // Crypto
    OP_SHA256 = 0xa8,
    OP_RIPEMD160 = 0xa6,
    OP_HASH160 = 0xa9,
    OP_HASH256 = 0xaa,
    OP_CHECKSIG = 0xac,
    OP_CHECKSIGVERIFY = 0xad,
    OP_CHECKMULTISIG = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,
}

impl From<u8> for Opcode {
    fn from(v: u8) -> Self {
        unsafe { std::mem::transmute(v) }
    }
}
