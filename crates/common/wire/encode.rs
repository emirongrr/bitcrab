//! Bitcoin binary wire format encoder.
//!
//! # Design
//!
//!
//!
//! Bitcoin Core ref: src/serialize.h READWRITE macro
//!
//! # Usage
//!
//! ```rust
//! use bitcrab_common::wire::encode::{BitcoinEncode, Encoder, VarStr};
//!
//! #[derive(Debug, PartialEq)]
//! struct Simple {
//!     pub a: u32,
//!     pub b: u64,
//! }
//!
//! impl BitcoinEncode for Simple {
//!     fn encode(&self, enc: Encoder) -> Encoder {
//!         enc.encode_field(&self.a)
//!            .encode_field(&self.b)
//!     }
//! }
//!
//! let s = Simple { a: 1, b: 2 };
//! let bytes = Encoder::new().encode_field(&s).finish();
//! assert_eq!(bytes.len(), 12); // 4 + 8
//! ```

/// Every type that can be encoded to Bitcoin wire format.
///
pub trait BitcoinEncode {
    fn encode(&self, enc: Encoder) -> Encoder;
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

/// Builder for Bitcoin wire format payloads.
///
/// Fark: RLP list prefix yok, doğrudan LE binary.
#[must_use = "Encoder must be consumed with finish()"]
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn with_capacity(n: usize) -> Self {
        Self {
            buf: Vec::with_capacity(n),
        }
    }

    /// Encode a field and chain.
    ///
    pub fn encode_field<T: BitcoinEncode>(self, value: &T) -> Self {
        value.encode(self)
    }

    /// Consume and return encoded bytes.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    // Internal write helpers — not pub, use encode_field instead
    pub(crate) fn push_u8(mut self, v: u8) -> Self {
        self.buf.push(v);
        self
    }

    pub(crate) fn push_bytes(mut self, v: &[u8]) -> Self {
        self.buf.extend_from_slice(v);
        self
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// BitcoinEncode — primitives
// ---------------------------------------------------------------------------

impl BitcoinEncode for u8 {
    fn encode(&self, enc: Encoder) -> Encoder {
        enc.push_u8(*self)
    }
}

impl BitcoinEncode for u32 {
    /// Little-endian u32.
    /// Bitcoin Core: standard LE integer serialization in src/serialize.h
    fn encode(&self, enc: Encoder) -> Encoder {
        enc.push_bytes(&self.to_le_bytes())
    }
}

impl BitcoinEncode for u64 {
    fn encode(&self, enc: Encoder) -> Encoder {
        enc.push_bytes(&self.to_le_bytes())
    }
}

impl BitcoinEncode for i32 {
    fn encode(&self, enc: Encoder) -> Encoder {
        enc.push_bytes(&self.to_le_bytes())
    }
}

impl BitcoinEncode for i64 {
    fn encode(&self, enc: Encoder) -> Encoder {
        enc.push_bytes(&self.to_le_bytes())
    }
}

impl BitcoinEncode for bool {
    fn encode(&self, enc: Encoder) -> Encoder {
        enc.push_u8(*self as u8)
    }
}

impl BitcoinEncode for [u8] {
    /// Raw bytes — no length prefix.
    fn encode(&self, enc: Encoder) -> Encoder {
        enc.push_bytes(self)
    }
}

impl<const N: usize> BitcoinEncode for [u8; N] {
    fn encode(&self, enc: Encoder) -> Encoder {
        enc.push_bytes(self)
    }
}

// ---------------------------------------------------------------------------
// Wrapper types for special encodings
// ---------------------------------------------------------------------------

/// Variable-length integer.
///
/// Bitcoin Core: `WriteCompactSize()` in src/serialize.h
///
/// Encoding:
/// ```text
/// 0x00–0xFC        → 1 byte
/// 0xFD–0xFFFF      → 0xFD + 2 bytes LE
/// 0x10000–0xFFFFFFFF → 0xFE + 4 bytes LE
/// else             → 0xFF + 8 bytes LE
/// ```
pub struct VarInt(pub u64);

impl BitcoinEncode for VarInt {
    fn encode(&self, enc: Encoder) -> Encoder {
        match self.0 {
            n @ 0x00..=0xFC => enc.push_u8(n as u8),
            n @ 0xFD..=0xFFFF => enc.push_u8(0xFD).push_bytes(&(n as u16).to_le_bytes()),
            n @ 0x10000..=0xFFFF_FFFF => enc.push_u8(0xFE).push_bytes(&(n as u32).to_le_bytes()),
            n => enc.push_u8(0xFF).push_bytes(&n.to_le_bytes()),
        }
    }
}

/// Variable-length string: VarInt(len) + UTF-8 bytes.
///
/// Bitcoin Core: `READWRITE(strSubVer)` in version message
pub struct VarStr<'a>(pub &'a str);

impl BitcoinEncode for VarStr<'_> {
    fn encode(&self, enc: Encoder) -> Encoder {
        let b = self.0.as_bytes();
        enc.encode_field(&VarInt(b.len() as u64)).push_bytes(b)
    }
}

/// 2-byte unsigned integer, big-endian.
///
/// Port numbers in addr/version messages are big-endian.
/// Bitcoin Core: CAddress port field
pub struct U16BE(pub u16);

impl BitcoinEncode for U16BE {
    fn encode(&self, enc: Encoder) -> Encoder {
        enc.push_bytes(&self.0.to_be_bytes())
    }
}

/// A list with a VarInt count prefix.
///
/// Bitcoin Core: most repeated fields use compact-size prefix
pub struct VarList<'a, T: BitcoinEncode>(pub &'a [T]);

impl<T: BitcoinEncode> BitcoinEncode for VarList<'_, T> {
    fn encode(&self, enc: Encoder) -> Encoder {
        let enc = enc.encode_field(&VarInt(self.0.len() as u64));
        self.0.iter().fold(enc, |e, item| item.encode(e))
    }
}
