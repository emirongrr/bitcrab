//! Wire format error types for Bitcoin binary encoding/decoding.
//!
//! crates/common/rlp/error.rs — adapted for Bitcoin's binary format.

use thiserror::Error;

/// Errors from Bitcoin wire format decoding.
///
/// Bitcoin Core does not have a unified decode error type —
/// failures are asserted or silently ignored in CDataStream.
/// We make every failure explicit and typed.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    /// Buffer ended before all required bytes were read.
    #[error("buffer too short reading '{field}': need {needed}, have {available}")]
    BufferTooShort {
        field: &'static str,
        needed: usize,
        available: usize,
    },

    /// A varint was truncated mid-encoding.
    #[error("truncated varint reading '{field}'")]
    TruncatedVarint { field: &'static str },

    /// A string field contained invalid UTF-8.
    #[error("invalid UTF-8 in field '{field}'")]
    InvalidUtf8 { field: &'static str },

    /// Bytes remained after a complete decode where none were expected.
    #[error("{remaining} trailing bytes after full decode of {context}")]
    TrailingBytes {
        context: &'static str,
        remaining: usize,
    },

    /// A field value was structurally valid but semantically out of range.
    #[error("field '{field}' value {value} is invalid")]
    InvalidValue { field: &'static str, value: u64 },

    /// Custom error with message — for cases not covered above.
    #[error("{0}")]
    Custom(String),
}
impl DecodeError {
    /// Attach field name to this decode error for logging/debug
    pub fn with_field(self, field: &'static str) -> Self {
        match self {
            DecodeError::BufferTooShort { needed, available, .. } => {
                DecodeError::BufferTooShort { field, needed, available }
            }
            DecodeError::TruncatedVarint { .. } => DecodeError::TruncatedVarint { field },
            DecodeError::InvalidUtf8 { .. } => DecodeError::InvalidUtf8 { field },
            DecodeError::InvalidValue { value, .. } => DecodeError::InvalidValue { field, value },
            other => other, // TrailingBytes ve Custom değişmeden kalır
        }
    }
}
/// Errors from Bitcoin wire format encoding.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EncodeError {
    /// A value was too large for its wire representation.
    #[error("field '{field}' value {value} exceeds maximum {max}")]
    ValueTooLarge {
        field: &'static str,
        value: u64,
        max: u64,
    },

    /// Custom error with message.
    #[error("{0}")]
    Custom(String),
}