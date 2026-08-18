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
use crate::types::constants::MAX_MESSAGE_SIZE;
use crate::wire::encode::VarInt;
use crate::wire::encode::U16BE;

const MAX_WIRE_ALLOCATION: usize = MAX_MESSAGE_SIZE;

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
#[derive(Clone, Copy)]
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

    /// Peek at the next byte without consuming it.
    pub fn peek_u8(self, field: &'static str) -> Result<u8, DecodeError> {
        self.require(1, field)?;
        Ok(self.data[self.pos])
    }

    /// Decode an optional field — returns None only if no bytes remain.
    ///
    pub fn decode_optional_field<T: BitcoinDecode>(self) -> Result<(Option<T>, Self), DecodeError> {
        if self.is_done() {
            return Ok((None, self));
        }
        let (v, dec) = T::decode(self)?;
        Ok((Some(v), dec))
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
        let (v, consumed) = read_varint_raw(&self.data[self.pos..], field)?;
        self.pos += consumed;
        Ok((v, self))
    }

    /// Read a VarInt-prefixed byte array.
    pub fn read_varbytes(self, label: &'static str) -> Result<(Vec<u8>, Self), DecodeError> {
        let (len, dec) = self.read_varint(label)?;
        ensure_allocation_len(label, len)?;
        dec.read_bytes(len as usize, label)
    }

    /// Read a VarInt-prefixed list of items.
    pub fn read_var_list<T: BitcoinDecode>(
        self,
        label: &'static str,
    ) -> Result<(Vec<T>, Self), DecodeError> {
        let (count, mut dec) = self.read_varint(label)?;
        ensure_allocation_len(label, count)?;
        if count as usize > dec.remaining() {
            return Err(DecodeError::AllocationTooLarge {
                field: label,
                len: count,
                limit: dec.remaining(),
            });
        }
        let mut items = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let (item, next_dec) = T::decode(dec)?;
            items.push(item);
            dec = next_dec;
        }
        Ok((items, dec))
    }

    pub fn read_bytes(
        mut self,
        n: usize,
        field: &'static str,
    ) -> Result<(Vec<u8>, Self), DecodeError> {
        self.require(n, field)?;
        let v = self.data[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok((v, self))
    }

    /// Read varint(len) + len bytes as UTF-8 string.
    pub fn read_var_str(mut self, field: &'static str) -> Result<(String, Self), DecodeError> {
        let (len, consumed) = read_varint_raw(&self.data[self.pos..], field)?;
        self.pos += consumed;
        ensure_allocation_len(field, len)?;
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

impl BitcoinDecode for Vec<u8> {
    /// Vector of bytes is decoded as VarBytes (VarInt length + bytes).
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        dec.read_varbytes("Vec<u8>")
    }
}

// ---------------------------------------------------------------------------
// Varint helper
// ---------------------------------------------------------------------------

pub(crate) fn read_varint_raw(
    buf: &[u8],
    field: &'static str,
) -> Result<(u64, usize), DecodeError> {
    match buf.first().ok_or(DecodeError::TruncatedVarint { field })? {
        &n @ 0x00..=0xFC => Ok((n as u64, 1)),
        0xFD => {
            if buf.len() < 3 {
                return Err(DecodeError::TruncatedVarint { field });
            }
            let value = u16::from_le_bytes(buf[1..3].try_into().unwrap()) as u64;
            if value < 0xFD {
                return Err(DecodeError::NonCanonicalVarint {
                    field,
                    value,
                    encoded_len: 3,
                });
            }
            Ok((value, 3))
        }
        0xFE => {
            if buf.len() < 5 {
                return Err(DecodeError::TruncatedVarint { field });
            }
            let value = u32::from_le_bytes(buf[1..5].try_into().unwrap()) as u64;
            if value < 0x1_0000 {
                return Err(DecodeError::NonCanonicalVarint {
                    field,
                    value,
                    encoded_len: 5,
                });
            }
            Ok((value, 5))
        }
        0xFF => {
            if buf.len() < 9 {
                return Err(DecodeError::TruncatedVarint { field });
            }
            let value = u64::from_le_bytes(buf[1..9].try_into().unwrap());
            if value < 0x1_0000_0000 {
                return Err(DecodeError::NonCanonicalVarint {
                    field,
                    value,
                    encoded_len: 9,
                });
            }
            Ok((value, 9))
        }
    }
}

fn ensure_allocation_len(field: &'static str, len: u64) -> Result<(), DecodeError> {
    if len > MAX_WIRE_ALLOCATION as u64 || len > usize::MAX as u64 {
        return Err(DecodeError::AllocationTooLarge {
            field,
            len,
            limit: MAX_WIRE_ALLOCATION,
        });
    }
    Ok(())
}

/// Decode a value and require that the whole payload was consumed.
pub fn decode_exact<T: BitcoinDecode>(
    payload: &[u8],
    context: &'static str,
) -> Result<T, DecodeError> {
    let (value, dec) = T::decode(Decoder::new(payload))?;
    dec.finish(context)?;
    Ok(value)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
