//! Bitcoin binary wire format decoder.
//!
//! # Design
//!
//! `BitcoinDecode` trait + `Decoder` builder.
//!
//!
//! Bitcoin Core ref: src/serialize.h CDataStream
//!
//! # Usage
//!
//! ```rust
//! use bitcrab_common::wire::decode::{BitcoinDecode, Decoder};
//! use bitcrab_common::wire::error::DecodeError;
//!
//! #[derive(Debug, PartialEq)]
//! struct Simple {
//!     pub a: u32,
//!     pub b: u64,
//! }
//!
//! impl BitcoinDecode for Simple {
//!     fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
//!         let (a, dec) = dec.decode_field("a")?;
//!         let (b, dec) = dec.decode_field("b")?;
//!         Ok((Simple { a, b }, dec))
//!     }
//! }
//!
//! let bytes = [1u8, 0, 0, 0,   // a = 1 (LE u32)
//!              2u8, 0, 0, 0, 0, 0, 0, 0]; // b = 2 (LE u64)
//! let (s, dec) = Simple::decode(Decoder::new(&bytes)).unwrap();
//! dec.finish("Simple").unwrap();
//! assert_eq!(s, Simple { a: 1, b: 2 });
//! ```

use super::error::DecodeError;
use crate::wire::encode::VarInt;
use crate::wire::encode::U16BE;

/// Every type that can be decoded from Bitcoin wire format.
///
pub trait BitcoinDecode: Sized {
    /// Decode from a Decoder, returning (Self, remaining Decoder).
    ///
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError>;
}

impl BitcoinDecode for VarInt {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        let (v, dec) = dec.read_varint("VarInt")?;
        Ok((VarInt(v), dec))
    }
}

impl<const N: usize> BitcoinDecode for [u8; N] {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        dec.read_array::<N>("array")
    }
}
// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

/// Cursor-based decoder for Bitcoin wire format payloads.
///
#[must_use = "Decoder must be consumed with finish() or finish_unchecked()"]
pub struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    /// Start decoding from a payload slice.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Decode the next field using its `BitcoinDecode` impl.
    ///
    pub fn decode_field<T: BitcoinDecode>(
        self,
        _name: &'static str,
    ) -> Result<(T, Self), DecodeError> {
        T::decode(self)
    }

    /// Decode an optional field — returns None if no bytes remain.
    ///
    pub fn decode_optional_field<T: BitcoinDecode>(self) -> (Option<T>, Self) {
        if self.is_done() {
            return (None, self);
        }
        match T::decode(self) {
            Ok((v, dec)) => (Some(v), dec),
            Err(_) => unreachable!(), // only called when bytes remain
        }
    }

    /// True if all bytes have been consumed.
    ///
    pub fn is_done(&self) -> bool {
        self.pos == self.data.len()
    }

    /// Assert all bytes consumed, error if not.
    ///
    pub fn finish(self, context: &'static str) -> Result<(), DecodeError> {
        if self.is_done() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes {
                context,
                remaining: self.data.len() - self.pos,
            })
        }
    }

    /// Finish without checking trailing bytes.
    /// Use when trailing optional fields may be absent.
    ///
    pub fn finish_unchecked(self) {}

    // -----------------------------------------------------------------------
    // Typed read methods — used by BitcoinDecode impls
    // -----------------------------------------------------------------------

    pub fn read_u8(mut self, field: &'static str) -> Result<(u8, Self), DecodeError> {
        self.require(1, field)?;
        let v = self.data[self.pos];
        self.pos += 1;
        Ok((v, self))
    }

    pub fn read_u16_le(mut self, field: &'static str) -> Result<(u16, Self), DecodeError> {
        self.require(2, field)?;
        let v = u16::from_le_bytes(self.data[self.pos..self.pos + 2].try_into().unwrap());
        self.pos += 2;
        Ok((v, self))
    }

    pub fn read_u32_le(mut self, field: &'static str) -> Result<(u32, Self), DecodeError> {
        self.require(4, field)?;
        let v = u32::from_le_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok((v, self))
    }

    pub fn read_u64_le(mut self, field: &'static str) -> Result<(u64, Self), DecodeError> {
        self.require(8, field)?;
        let v = u64::from_le_bytes(self.data[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok((v, self))
    }

    pub fn read_i32_le(mut self, field: &'static str) -> Result<(i32, Self), DecodeError> {
        self.require(4, field)?;
        let v = i32::from_le_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok((v, self))
    }

    pub fn read_i64_le(mut self, field: &'static str) -> Result<(i64, Self), DecodeError> {
        self.require(8, field)?;
        let v = i64::from_le_bytes(self.data[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok((v, self))
    }

    pub fn read_u16_be(mut self, field: &'static str) -> Result<(u16, Self), DecodeError> {
        self.require(2, field)?;
        let v = u16::from_be_bytes(self.data[self.pos..self.pos + 2].try_into().unwrap());
        self.pos += 2;
        Ok((v, self))
    }

    pub fn read_bool(mut self, field: &'static str) -> Result<(bool, Self), DecodeError> {
        self.require(1, field)?;
        let v = self.data[self.pos] != 0;
        self.pos += 1;
        Ok((v, self))
    }

    pub fn read_array<const N: usize>(
        mut self,
        field: &'static str,
    ) -> Result<([u8; N], Self), DecodeError> {
        self.require(N, field)?;
        let v: [u8; N] = self.data[self.pos..self.pos + N].try_into().unwrap();
        self.pos += N;
        Ok((v, self))
    }

    /// Read a varint.
    ///
    /// Bitcoin Core: `ReadCompactSize()` in src/serialize.h
    pub fn read_varint(mut self, field: &'static str) -> Result<(u64, Self), DecodeError> {
        let (v, consumed) = read_varint_raw(&self.data[self.pos..])
            .ok_or(DecodeError::TruncatedVarint { field })?;
        self.pos += consumed;
        Ok((v, self))
    }

    /// Read varint(len) + len bytes as UTF-8 string.
    pub fn read_var_str(mut self, field: &'static str) -> Result<(String, Self), DecodeError> {
        let (len, consumed) = read_varint_raw(&self.data[self.pos..])
            .ok_or(DecodeError::TruncatedVarint { field })?;
        self.pos += consumed;
        let len = len as usize;
        self.require(len, field)?;
        let s = std::str::from_utf8(&self.data[self.pos..self.pos + len])
            .map_err(|_| DecodeError::InvalidUtf8 { field })?
            .to_string();
        self.pos += len;
        Ok((s, self))
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn require(&self, n: usize, field: &'static str) -> Result<(), DecodeError> {
        if self.remaining() < n {
            Err(DecodeError::BufferTooShort {
                field,
                needed: self.pos + n,
                available: self.data.len(),
            })
        } else {
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// BitcoinDecode — primitives
// ---------------------------------------------------------------------------

impl BitcoinDecode for u8 {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        dec.read_u8("u8")
    }
}

impl BitcoinDecode for U16BE {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        let (v, dec) = dec.read_u16_be("U16BE")?;
        Ok((U16BE(v), dec))
    }
}
impl BitcoinDecode for u32 {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        dec.read_u32_le("u32")
    }
}

impl BitcoinDecode for u64 {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        dec.read_u64_le("u64")
    }
}

impl BitcoinDecode for i32 {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        dec.read_i32_le("i32")
    }
}

impl BitcoinDecode for i64 {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        dec.read_i64_le("i64")
    }
}

impl BitcoinDecode for bool {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        dec.read_bool("bool")
    }
}

// ---------------------------------------------------------------------------
// Varint helper
// ---------------------------------------------------------------------------

pub(crate) fn read_varint_raw(buf: &[u8]) -> Option<(u64, usize)> {
    match buf.first()? {
        &n @ 0x00..=0xFC => Some((n as u64, 1)),
        0xFD => {
            if buf.len() < 3 { return None; }
            Some((u16::from_le_bytes(buf[1..3].try_into().unwrap()) as u64, 3))
        }
        0xFE => {
            if buf.len() < 5 { return None; }
            Some((u32::from_le_bytes(buf[1..5].try_into().unwrap()) as u64, 5))
        }
        0xFF => {
            if buf.len() < 9 { return None; }
            Some((u64::from_le_bytes(buf[1..9].try_into().unwrap()), 9))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

