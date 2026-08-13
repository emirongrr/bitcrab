//! Script numbers.
//!
//! Bitcoin Core: `CScriptNum` in `src/script/script.h`.
//!
//! Script integers are little-endian, sign-magnitude (the high bit of the last
//! byte is the sign), and variable length. Arithmetic opcodes reject inputs
//! longer than 4 bytes even though the *result* may exceed that range, which is
//! why the limit is a decode-time parameter rather than a type invariant.

use crate::error::{ScriptError, ScriptResult};

/// Default maximum encoded length accepted by arithmetic opcodes.
///
/// Bitcoin Core: `nDefaultMaxNumSize = 4`.
pub const DEFAULT_MAX_NUM_SIZE: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScriptNum(pub i64);

impl ScriptNum {
    /// Decode a stack element as a number.
    ///
    /// `require_minimal` corresponds to `SCRIPT_VERIFY_MINIMALDATA`.
    ///
    /// Bitcoin Core: `CScriptNum::CScriptNum(const std::vector<unsigned char>&, bool, size_t)`.
    pub fn decode(data: &[u8], require_minimal: bool, max_size: usize) -> ScriptResult<Self> {
        if data.len() > max_size {
            return Err(ScriptError::UnknownError);
        }

        if require_minimal && !is_minimally_encoded(data) {
            return Err(ScriptError::MinimalData);
        }

        Ok(Self(decode_unchecked(data)))
    }

    /// Encode as a stack element.
    ///
    /// Bitcoin Core: `CScriptNum::serialize()`.
    pub fn encode(self) -> Vec<u8> {
        let value = self.0;
        if value == 0 {
            return Vec::new();
        }

        let negative = value < 0;
        let mut absolute = value.unsigned_abs();
        let mut result = Vec::with_capacity(9);

        while absolute > 0 {
            result.push((absolute & 0xff) as u8);
            absolute >>= 8;
        }

        // If the most significant byte already uses its high bit, the sign has
        // to go in a new byte or it would be read back as negative.
        if result.last().is_some_and(|last| last & 0x80 != 0) {
            result.push(if negative { 0x80 } else { 0x00 });
        } else if negative {
            let last = result.len() - 1;
            result[last] |= 0x80;
        }

        result
    }

    pub fn as_i64(self) -> i64 {
        self.0
    }
}

/// Decode without any length or minimality checks.
fn decode_unchecked(data: &[u8]) -> i64 {
    if data.is_empty() {
        return 0;
    }

    let mut result: i64 = 0;
    for (i, &byte) in data.iter().enumerate() {
        result |= (byte as i64) << (8 * i);
    }

    // The high bit of the final byte is the sign, not part of the magnitude.
    if data[data.len() - 1] & 0x80 != 0 {
        let sign_mask = !(0x80i64 << (8 * (data.len() - 1)));
        return -(result & sign_mask);
    }

    result
}

/// True if `data` is the shortest encoding of its value.
///
/// Bitcoin Core: the minimality branch of `CScriptNum`'s constructor.
pub fn is_minimally_encoded(data: &[u8]) -> bool {
    let Some(&last) = data.last() else {
        return true; // empty == 0, always minimal
    };

    // A trailing 0x00/0x80 is redundant unless it exists purely to carry the
    // sign bit for the byte below it.
    if last & 0x7f == 0 {
        return data.len() > 1 && data[data.len() - 2] & 0x80 != 0;
    }

    true
}

/// Interpret a stack element as a boolean.
///
/// Bitcoin Core: `CastToBool()` in `src/script/interpreter.cpp`. Note that
/// negative zero (`0x80`) is false.
pub fn cast_to_bool(data: &[u8]) -> bool {
    for (i, &byte) in data.iter().enumerate() {
        if byte != 0 {
            // Negative zero is still zero.
            return !(i == data.len() - 1 && byte == 0x80);
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(value: i64) {
        let encoded = ScriptNum(value).encode();
        let decoded = ScriptNum::decode(&encoded, true, 8).unwrap();
        assert_eq!(decoded.0, value, "roundtrip failed for {}", value);
    }

    #[test]
    fn roundtrips_representative_values() {
        for value in [
            0,
            1,
            -1,
            2,
            -2,
            127,
            -127,
            128,
            -128,
            129,
            -129,
            255,
            -255,
            256,
            -256,
            32767,
            -32767,
            65535,
            -65535,
            16_777_215,
            -16_777_215,
            2_147_483_647,
            -2_147_483_647,
        ] {
            roundtrip(value);
        }
    }

    #[test]
    fn zero_encodes_as_the_empty_element() {
        assert_eq!(ScriptNum(0).encode(), Vec::<u8>::new());
    }

    #[test]
    fn encoding_matches_known_bitcoin_vectors() {
        assert_eq!(ScriptNum(1).encode(), vec![0x01]);
        assert_eq!(ScriptNum(-1).encode(), vec![0x81]);
        assert_eq!(ScriptNum(127).encode(), vec![0x7f]);
        // 128 needs a sign byte: 0x80 alone would decode as negative zero.
        assert_eq!(ScriptNum(128).encode(), vec![0x80, 0x00]);
        assert_eq!(ScriptNum(-128).encode(), vec![0x80, 0x80]);
        assert_eq!(ScriptNum(256).encode(), vec![0x00, 0x01]);
    }

    #[test]
    fn non_minimal_encodings_are_rejected_only_when_required() {
        let padded = vec![0x01, 0x00]; // 1, with a redundant zero byte
        assert_eq!(
            ScriptNum::decode(&padded, true, 4),
            Err(ScriptError::MinimalData)
        );
        assert_eq!(ScriptNum::decode(&padded, false, 4).unwrap().0, 1);
    }

    #[test]
    fn sign_carrying_padding_is_minimal() {
        // 0x80,0x00 is the minimal encoding of 128 — the trailing 0x00 exists
        // solely so the 0x80 is not read as a sign bit.
        assert!(is_minimally_encoded(&[0x80, 0x00]));
        assert!(!is_minimally_encoded(&[0x01, 0x00]));
        assert!(is_minimally_encoded(&[]));
    }

    #[test]
    fn oversized_numbers_are_rejected() {
        let five_bytes = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        assert!(ScriptNum::decode(&five_bytes, false, DEFAULT_MAX_NUM_SIZE).is_err());
        assert!(ScriptNum::decode(&five_bytes, false, 5).is_ok());
    }

    #[test]
    fn cast_to_bool_treats_negative_zero_as_false() {
        assert!(!cast_to_bool(&[]));
        assert!(!cast_to_bool(&[0x00]));
        assert!(!cast_to_bool(&[0x00, 0x00]));
        assert!(!cast_to_bool(&[0x80]), "negative zero must be false");
        assert!(!cast_to_bool(&[0x00, 0x80]), "negative zero must be false");
        assert!(cast_to_bool(&[0x01]));
        assert!(cast_to_bool(&[0x00, 0x01]));
        assert!(cast_to_bool(&[0x81]));
    }
}
