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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::encode::{BitcoinEncode, Encoder, VarStr};

    /// Simple struct — encode_field / decode_field pattern.
    #[derive(Debug, PartialEq)]
    struct Simple {
        a: u32,
        b: u64,
    }

    impl BitcoinEncode for Simple {
        fn encode(&self, enc: Encoder) -> Encoder {
            enc.encode_field(&self.a)
               .encode_field(&self.b)
        }
    }

    impl BitcoinDecode for Simple {
        fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
            let (a, dec) = dec.decode_field("a")?;
            let (b, dec) = dec.decode_field("b")?;
            Ok((Simple { a, b }, dec))
        }
    }

    #[test]
    fn simple_roundtrip() {
        let original = Simple { a: 0xDEAD_BEEF, b: 0x0102_0304_0506_0708 };
        let bytes = Encoder::new().encode_field(&original).finish();
        assert_eq!(bytes.len(), 12); // 4 + 8

        let (decoded, dec) = Simple::decode(Decoder::new(&bytes)).unwrap();
        dec.finish("Simple").unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn u32_le_encoding() {
        let bytes = Encoder::new().encode_field(&0x0102_0304u32).finish();
        assert_eq!(bytes, [0x04, 0x03, 0x02, 0x01]); // little-endian
    }

    #[test]
    fn var_str_roundtrip() {
        let ua = "/bitcrab:0.1.0/";
        let bytes = Encoder::new().encode_field(&VarStr(ua)).finish();
        // varint(15) + 15 bytes = 16 bytes total
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[0], 15); // varint prefix
        let (decoded, dec) = Decoder::new(&bytes).read_var_str("ua").unwrap();
        dec.finish("var_str").unwrap();
        assert_eq!(decoded, ua);
    }

    #[test]
    fn varint_1_byte() {
        let bytes = Encoder::new().encode_field(&crate::wire::encode::VarInt(42)).finish();
        assert_eq!(bytes, [42]);
    }

    #[test]
    fn varint_3_byte() {
        // 0xFD..=0xFFFF → 0xFD prefix + 2 bytes LE
        let bytes = Encoder::new().encode_field(&crate::wire::encode::VarInt(300)).finish();
        assert_eq!(bytes[0], 0xFD);
        assert_eq!(bytes.len(), 3);
        let (v, _) = Decoder::new(&bytes).read_varint("v").unwrap();
        assert_eq!(v, 300);
    }

    #[test]
    fn trailing_bytes_detected() {
        let bytes = vec![1u8, 0, 0, 0, 0xFF]; // u32 + extra
        let (_, dec) = Decoder::new(&bytes).read_u32_le("v").unwrap();
        assert!(dec.finish("test").is_err());
    }

    #[test]
    fn optional_field_absent() {
        let bytes = Encoder::new().encode_field(&42u32).finish();
        let dec = Decoder::new(&bytes);
        let (v, dec): (u32, _) = dec.decode_field("v").unwrap();
        assert_eq!(v, 42);
        let (opt, _dec): (Option<u32>, _) = dec.decode_optional_field();
        assert!(opt.is_none()); // no bytes remain
    }

    #[test]
    fn bool_encoding() {
        let t = Encoder::new().encode_field(&true).finish();
        let f = Encoder::new().encode_field(&false).finish();
        assert_eq!(t, [0x01]);
        assert_eq!(f, [0x00]);
    }


    #[test]
fn port_must_use_u16be() {
    // Bitcoin port encoding is always big-endian
    // Bitcoin Core: CAddress port field in src/netaddress.h
    let port: u16 = 8333;
    let bytes = Encoder::new().encode_field(&U16BE(port)).finish();
    assert_eq!(bytes, [0x20, 0x8D]); // 8333 big-endian = 0x208D
    
    let (U16BE(decoded), dec) = U16BE::decode(Decoder::new(&bytes)).unwrap();
    dec.finish("port").unwrap();
    assert_eq!(decoded, 8333);
}

#[test]
fn fixed_array_roundtrip() {
    let hash = [0xABu8; 32];
    let bytes = Encoder::new().encode_field(&hash).finish();
    assert_eq!(bytes.len(), 32);
    let (decoded, dec): ([u8; 32], _) = Decoder::new(&bytes).decode_field("hash").unwrap();
    dec.finish("hash").unwrap();
    assert_eq!(decoded, hash);
}

#[test]
fn varint_decode_field() {
    use crate::wire::encode::VarInt;
    let bytes = Encoder::new().encode_field(&VarInt(2000)).finish();
    let (VarInt(v), dec): (VarInt, _) = Decoder::new(&bytes).decode_field("count").unwrap();
    dec.finish("count").unwrap();
    assert_eq!(v, 2000);
}
}