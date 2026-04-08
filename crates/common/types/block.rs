//! Bitcoin block types.
//!
//! # Bitcoin Core
//!
//! `CBlockHeader`, `CBlock` in `src/primitives/block.h`
//! Serialization via `SERIALIZE_METHODS` macro.
//!
//! We keep serialization as explicit methods — no macros.

use super::{
    hash::{hash256, BlockHash, Hash256},
    flat_file_pos::FlatFilePos,
};
use crate::wire::{
    decode::{BitcoinDecode, Decoder},
    encode::{BitcoinEncode, Encoder},
    error::DecodeError,
};

/// Block height from genesis. Genesis = height 0.
///
/// Bitcoin Core uses plain `int` for height, allowing -1 for "unknown".
/// We model unknown height as `Option<BlockHeight>` — clearer and safer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct BlockHeight(pub u32);

impl BlockHeight {
    /// The genesis block height.
    pub const GENESIS: Self = Self(0);

    /// One block higher.
    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    /// One block lower. Returns `None` at genesis.
    pub fn prev(self) -> Option<Self> {
        self.0.checked_sub(1).map(Self)
    }
}

impl std::fmt::Display for BlockHeight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl BitcoinEncode for BlockHeight {
    fn encode(&self, enc: Encoder) -> Encoder {
        enc.encode_field(&self.0)
    }
}
impl BitcoinDecode for BlockHeight {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        let (val, dec) = dec.decode_field::<u32>("BlockHeight")?;
        Ok((Self(val), dec))
    }
}

/// An 80-byte Bitcoin block header.
///
/// Bitcoin Core: `CBlockHeader` in `src/primitives/block.h`
///
/// Wire format (all fields little-endian):
/// ```text
/// offset  size  field
/// 0       4     version
/// 4       32    prev_hash
/// 36      32    merkle_root
/// 68      4     time
/// 72      4     bits
/// 76      4     nonce
/// ```
///
/// Block hash = hash256(these 80 bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    /// Block version — encodes softfork signals (BIP-9).
    /// Bitcoin Core: `int32_t nVersion`
    pub version: i32,

    /// Hash of the previous block header.
    /// All-zero at genesis.
    /// Bitcoin Core: `uint256 hashPrevBlock`
    pub prev_hash: BlockHash,

    /// Merkle root of all transactions.
    /// Bitcoin Core: `uint256 hashMerkleRoot`
    pub merkle_root: Hash256,

    /// Unix timestamp. Must be > median of previous 11 blocks (BIP-113).
    /// Bitcoin Core: `uint32_t nTime`
    pub time: u32,

    /// Compact proof-of-work target.
    /// Bitcoin Core: `uint32_t nBits`
    pub bits: u32,

    /// Proof-of-work nonce.
    /// Bitcoin Core: `uint32_t nNonce`
    pub nonce: u32,
}

impl BlockHeader {
    /// Serialize to the 80-byte wire format.
    ///
    /// Bitcoin Core: `CBlockHeader::Serialize()` via `SERIALIZE_METHODS`
    pub fn serialize(&self) -> [u8; 80] {
        let mut buf = [0u8; 80];
        buf[0..4].copy_from_slice(&self.version.to_le_bytes());
        buf[4..36].copy_from_slice(self.prev_hash.as_bytes());
        buf[36..68].copy_from_slice(self.merkle_root.as_bytes());
        buf[68..72].copy_from_slice(&self.time.to_le_bytes());
        buf[72..76].copy_from_slice(&self.bits.to_le_bytes());
        buf[76..80].copy_from_slice(&self.nonce.to_le_bytes());
        buf
    }

    /// Deserialize from the 80-byte wire format.
    pub fn deserialize(buf: &[u8; 80]) -> Self {
        Self {
            version:     i32::from_le_bytes(buf[0..4].try_into().unwrap()),
            prev_hash:   BlockHash::from_bytes(buf[4..36].try_into().unwrap()),
            merkle_root: Hash256::from_bytes(buf[36..68].try_into().unwrap()),
            time:        u32::from_le_bytes(buf[68..72].try_into().unwrap()),
            bits:        u32::from_le_bytes(buf[72..76].try_into().unwrap()),
            nonce:       u32::from_le_bytes(buf[76..80].try_into().unwrap()),
        }
    }

    /// Compute block hash = hash256(serialize(self)).
    ///
    /// Bitcoin Core: `CBlockHeader::GetHash()` in `src/primitives/block.h`
    pub fn block_hash(&self) -> BlockHash {
        BlockHash::from_bytes(hash256(&self.serialize()))
    }

    /// Decode the compact `bits` field into a 32-byte big-endian target.
    ///
    /// Format: bits[31:24] = exponent, bits[23:0] = mantissa
    /// Target = mantissa × 256^(exponent - 3)
    ///
    /// Bitcoin Core: `arith_uint256::SetCompact()` in `src/arith_uint256.cpp`
    pub fn target(&self) -> [u8; 32] {
        let exponent = (self.bits >> 24) as usize;
        let mantissa = self.bits & 0x007F_FFFF;
        let mut target = [0u8; 32];
        if exponent == 0 || exponent > 34 {
            return target;
        }
        let pos = 32usize.saturating_sub(exponent);
        if pos     < 32 { target[pos]     = ((mantissa >> 16) & 0xFF) as u8; }
        if pos + 1 < 32 { target[pos + 1] = ((mantissa >>  8) & 0xFF) as u8; }
        if pos + 2 < 32 { target[pos + 2] = ( mantissa        & 0xFF) as u8; }
        target
    }

    /// True if hash < target (valid proof-of-work).
    ///
    /// Bitcoin Core: `CheckProofOfWork()` in `src/pow.cpp`
    pub fn meets_target(&self) -> bool {
        let mut hash_be = *self.block_hash().as_bytes();
        hash_be.reverse();
        hash_be.as_slice() < self.target().as_slice()
    }
}

impl BitcoinEncode for BlockHeader {
    fn encode(&self, enc: Encoder) -> Encoder {
        enc.push_bytes(&self.serialize())
    }
}
impl BitcoinDecode for BlockHeader {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        let (bytes, dec) = dec.decode_field::<[u8; 80]>("BlockHeader")?;
        Ok((Self::deserialize(&bytes), dec))
    }
}

// ---------------------------------------------------------------------------
// Block errors
// ---------------------------------------------------------------------------

/// Errors from block header validation.
///
/// Bitcoin Core: `CheckBlockHeader()` and `ContextualCheckBlockHeader()`
/// in `src/validation.cpp` — errors carried as strings in `BlockValidationState`.
/// We use typed variants.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BlockError {
    /// Hash does not meet the proof-of-work target.
    /// Bitcoin Core: `CheckProofOfWork()` — `src/pow.cpp:12`
    #[error("proof of work invalid: hash {hash} does not meet target for bits {bits:#010x}")]
    InsufficientProofOfWork { hash: String, bits: u32 },

    /// `bits` encodes an invalid target (zero, negative, or overflow).
    /// Bitcoin Core: `GetCompact()` checks in `src/arith_uint256.cpp`
    #[error("bits {0:#010x} encodes an invalid target")]
    InvalidBits(u32),

    /// Timestamp is more than 2 hours ahead of network time.
    /// Bitcoin Core: `MAX_FUTURE_BLOCK_TIME = 7200` — `src/chain.h`
    #[error(
        "block time {block_time} is {drift}s ahead of network time \
         {network_time} (max {max_drift}s)"
    )]
    TimestampTooFar {
        block_time: u32,
        network_time: u32,
        drift: u32,
        max_drift: u32,
    },

    /// Timestamp not greater than Median Time Past (BIP-113).
    /// Bitcoin Core: `ContextualCheckBlockHeader()` — `src/validation.cpp`
    #[error(
        "block time {block_time} must be greater than median time past {median_time_past}"
    )]
    TimestampBelowMedianTimePast {
        block_time: u32,
        median_time_past: u32,
    },

    /// `bits` does not match the required difficulty at this height.
    /// Bitcoin Core: `GetNextWorkRequired()` comparison
    #[error(
        "wrong difficulty at height {height}: got {actual:#010x}, expected {expected:#010x}"
    )]
    WrongDifficulty { height: u32, actual: u32, expected: u32 },
}

// ---------------------------------------------------------------------------
// Block index
// ---------------------------------------------------------------------------

/// Metadata about a block in the chain.
///
/// Bitcoin Core: `CBlockIndex` in `src/chain.h`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockIndex {
    pub header:   BlockHeader,
    pub height:   BlockHeight,
    pub file_pos: Option<FlatFilePos>,
    pub undo_pos: Option<FlatFilePos>,
}

impl BitcoinEncode for BlockIndex {
    fn encode(&self, enc: Encoder) -> Encoder {
        enc.encode_field(&self.header)
           .encode_field(&self.height)
           .encode_field(&self.file_pos.is_some())
           .encode_field(&self.file_pos.unwrap_or(FlatFilePos::new(0, 0)))
           .encode_field(&self.undo_pos.is_some())
           .encode_field(&self.undo_pos.unwrap_or(FlatFilePos::new(0, 0)))
    }
}

impl BitcoinDecode for BlockIndex {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        let (header, dec) = dec.decode_field::<BlockHeader>("BlockIndex::header")?;
        let (height, dec) = dec.decode_field::<BlockHeight>("BlockIndex::height")?;
        
        let (has_pos, dec) = dec.decode_field::<bool>("BlockIndex::has_pos")?;
        let (pos,     dec) = dec.decode_field::<FlatFilePos>("BlockIndex::pos")?;
        let file_pos = if has_pos { Some(pos) } else { None };

        let (has_undo, dec) = dec.decode_field::<bool>("BlockIndex::has_undo")?;
        let (undo,     dec) = dec.decode_field::<FlatFilePos>("BlockIndex::undo")?;
        let undo_pos = if has_undo { Some(undo) } else { None };

        Ok((BlockIndex { header, height, file_pos, undo_pos }, dec))
    }
}
