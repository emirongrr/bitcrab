//! Bitcoin hash types.
//!
//! Each hash type is a distinct struct. Mixing Txid with BlockHash
//! is a compile error — no runtime cost, no macro magic.
//!
//! Bitcoin Core uses uint256 for everything. We use distinct types.

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use std::fmt;

// ---------------------------------------------------------------------------
// Hash functions
// ---------------------------------------------------------------------------

/// SHA-256(SHA-256(data)) — the primary Bitcoin hash function.
///
/// Bitcoin Core: `CHash256` in src/hash.h
pub fn hash256(data: &[u8]) -> [u8; 32] {
    let first  = Sha256::digest(data);
    let second = Sha256::digest(first);
    second.into()
}

/// RIPEMD-160(SHA-256(data)) — used for address derivation.
///
/// Bitcoin Core: `CHash160` in src/hash.h
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha  = Sha256::digest(data);
    let ripe = Ripemd160::digest(sha);
    ripe.into()
}

// ---------------------------------------------------------------------------
// Hash256
// ---------------------------------------------------------------------------

/// A SHA-256(SHA-256(x)) digest.
///
/// Used for: block hashes, txids, merkle nodes, sighash digests.
/// Bitcoin Core: uint256 in src/uint256.h — but used for everything.
/// We use distinct types to prevent mixing at compile time.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hash256([u8; 32]);

impl Hash256 {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn hash(data: &[u8]) -> Self {
        Self(hash256(data))
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    pub const ZERO: Self = Self([0u8; 32]);
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash256({})", hex::encode(self.0))
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut r = self.0;
        r.reverse();
        write!(f, "{}", hex::encode(r))
    }
}

// ---------------------------------------------------------------------------
// BlockHash
// ---------------------------------------------------------------------------

/// A block header hash.
///
/// Distinct from Txid — the compiler prevents mixing these two.
/// Bitcoin Core uses uint256 for both, which caused real bugs historically.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct BlockHash([u8; 32]);

impl BlockHash {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_hash256(h: Hash256) -> Self {
        Self(*h.as_bytes())
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    pub const ZERO: Self = Self([0u8; 32]);
}

impl fmt::Debug for BlockHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlockHash({})", hex::encode(self.0))
    }
}

impl fmt::Display for BlockHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut r = self.0;
        r.reverse();
        write!(f, "{}", hex::encode(r))
    }
}

// ---------------------------------------------------------------------------
// Txid
// ---------------------------------------------------------------------------

/// A transaction id — hash256 of the legacy (non-witness) serialization.
///
/// Not the same as wtxid (which includes witness data).
/// Bitcoin Core: uint256 — same type as BlockHash, which caused bugs.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Txid([u8; 32]);

impl Txid {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn hash(data: &[u8]) -> Self {
        Self(hash256(data))
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    pub const ZERO: Self = Self([0u8; 32]);
}

impl fmt::Debug for Txid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Txid({})", hex::encode(self.0))
    }
}

impl fmt::Display for Txid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut r = self.0;
        r.reverse();
        write!(f, "{}", hex::encode(r))
    }
}

// ---------------------------------------------------------------------------
// Hash160
// ---------------------------------------------------------------------------

/// RIPEMD-160(SHA-256(x)) — 20-byte digest.
///
/// Used for: P2PKH address derivation, P2SH script hashes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hash160([u8; 20]);

impl Hash160 {
    pub fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    pub fn hash(data: &[u8]) -> Self {
        Self(hash160(data))
    }

    pub const ZERO: Self = Self([0u8; 20]);
}

impl fmt::Debug for Hash160 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash160({})", hex::encode(self.0))
    }
}

impl fmt::Display for Hash160 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

// ---------------------------------------------------------------------------
// HashError
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HashError {
    #[error("{context} requires {expected} bytes, got {actual}")]
    WrongLength {
        context: &'static str,
        expected: usize,
        actual: usize,
    },

    #[error("invalid hex for {context}: {reason}")]
    InvalidHex {
        context: &'static str,
        reason: &'static str,
    },
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

