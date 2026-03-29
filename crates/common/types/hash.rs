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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash256_empty_input_known_vector() {
        assert_eq!(
            hex::encode(hash256(b"")),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
        );
    }

    #[test]
    fn hash160_empty_input_known_vector() {
        assert_eq!(
            hex::encode(hash160(b"")),
            "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb",
        );
    }

    #[test]
    fn display_reverses_bytes() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xAB;
        bytes[1] = 0xCD;
        let h = Hash256::from_bytes(bytes);
        let s = h.to_string();
        assert!(s.starts_with("00"));
        assert!(s.ends_with("cdab"));
    }
    #[test]
    fn genesis_txid_known_value() {
        let txid = Txid::from_bytes(
            hex::decode(
                "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
            )
            .unwrap()
            .try_into()
            .unwrap(),
        );
            assert_eq!(
                txid.to_string(),
                "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
            );
    }

    #[test]
    fn txid_and_blockhash_are_distinct_types() {
        let _t: Txid      = Txid::ZERO;
        let _b: BlockHash = BlockHash::ZERO;
    }

    #[test]
    fn is_zero_works() {
        assert!(Hash256::ZERO.is_zero());
        assert!(!Hash256::from_bytes([1u8; 32]).is_zero());
    }
}