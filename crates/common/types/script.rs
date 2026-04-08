//! Script byte buffer.
//!
//! Full script execution lives in a future `script` module.
//! This type holds raw script bytes so that `TxIn` and `TxOut`
//! can reference scripts without pulling in the interpreter.
//!
//! Bitcoin Core: `CScript` in `src/script/script.h`
//! CScript inherits from std::vector<unsigned char> and adds
//! operator<< for building scripts. We use a plain newtype —
//! script building will be a separate concern.

use super::constants::MAX_SCRIPT_SIZE;

/// An opaque Bitcoin script — a sequence of bytes.
///
/// Does not interpret or validate the script contents.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ScriptBuf(Vec<u8>);

impl ScriptBuf {
    /// Empty script.
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Construct from raw bytes. No validation.
    pub fn from_bytes(v: Vec<u8>) -> Self {
        Self(v)
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True if the script is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// True if this script is within the consensus size limit.
    ///
    /// Bitcoin Core: `MAX_SCRIPT_SIZE` check in `src/script/script.h`
    pub fn is_within_size_limit(&self) -> bool {
        self.0.len() <= MAX_SCRIPT_SIZE
    }
}

impl From<Vec<u8>> for ScriptBuf {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl From<&[u8]> for ScriptBuf {
    fn from(s: &[u8]) -> Self {
        Self(s.to_vec())
    }
}

// ---------------------------------------------------------------------------
// Script errors (context-free, size/format only)
// ---------------------------------------------------------------------------

/// Errors from script parsing and resource limit checks.
///
/// Bitcoin Core: `ScriptError` in `src/script/script_error.h`
/// We define only what `common` needs — interpreter errors come later.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ScriptError {
    /// Script exceeds `MAX_SCRIPT_SIZE`.
    ///
    /// Bitcoin Core: `MAX_SCRIPT_SIZE = 10000` in `src/script/script.h`
    #[error("script size {actual} exceeds MAX_SCRIPT_SIZE ({max})")]
    TooLarge { actual: usize, max: usize },

    /// A push data element exceeds `MAX_SCRIPT_ELEMENT_SIZE`.
    ///
    /// Bitcoin Core: `MAX_SCRIPT_ELEMENT_SIZE = 520` in `src/script/script.h`
    #[error(
        "push data at offset {offset} is {actual} bytes, \
         exceeds MAX_SCRIPT_ELEMENT_SIZE ({max})"
    )]
    ElementTooLarge {
        offset: usize,
        actual: usize,
        max: usize,
    },

    /// Truncated push data — script ends before push data bytes.
    #[error(
        "push data at offset {offset} claims {claimed} bytes \
         but only {available} remain"
    )]
    TruncatedPushData {
        offset: usize,
        claimed: usize,
        available: usize,
    },
}
