//! Bitcoin block types.
//!
//! # Bitcoin Core
//!
//! `CBlockHeader`, `CBlock` in `src/primitives/block.h`
//! Serialization via `SERIALIZE_METHODS` macro.
//!
//! We keep serialization as explicit methods — no macros.

use super::{
    flat_file_pos::FlatFilePos,
    hash::{hash256, BlockHash, Hash256},
    transaction::Transaction,
};
use crate::wire::{
    decode::{BitcoinDecode, Decoder},
    encode::{BitcoinEncode, Encoder, VarList},
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
            version: i32::from_le_bytes(buf[0..4].try_into().unwrap()),
            prev_hash: BlockHash::from_bytes(buf[4..36].try_into().unwrap()),
            merkle_root: Hash256::from_bytes(buf[36..68].try_into().unwrap()),
            time: u32::from_le_bytes(buf[68..72].try_into().unwrap()),
            bits: u32::from_le_bytes(buf[72..76].try_into().unwrap()),
            nonce: u32::from_le_bytes(buf[76..80].try_into().unwrap()),
        }
    }

    /// Compute block hash = hash256(serialize(self)).
    ///
    /// Bitcoin Core: `CBlockHeader::GetHash()` in `src/primitives/block.h`
    pub fn block_hash(&self) -> BlockHash {
        BlockHash::from_bytes(hash256(&self.serialize()))
    }

    /// Decode the compact `bits` field into a 32-byte target.
    ///
    /// Bitcoin Core: `arith_uint256::SetCompact()` in `src/arith_uint256.cpp`
    pub fn target(&self) -> Hash256 {
        Self::bits_to_target(self.bits)
    }

    /// Convert compact bits to a 256-bit target.
    pub fn bits_to_target(bits: u32) -> Hash256 {
        let exponent = (bits >> 24) as usize;
        let mantissa = bits & 0x00FF_FFFF;
        let mut target = [0u8; 32];

        if exponent == 0 {
            return Hash256::from_bytes(target);
        }

        let pos = exponent.saturating_sub(3);

        let m0 = (mantissa & 0xFF) as u8;
        let m1 = ((mantissa >> 8) & 0xFF) as u8;
        let m2 = ((mantissa >> 16) & 0xFF) as u8;

        if pos < 32 {
            target[pos] = m0;
        }
        if pos + 1 < 32 {
            target[pos + 1] = m1;
        }
        if pos + 2 < 32 {
            target[pos + 2] = m2;
        }

        // Note: Bitcoin's SetCompact also handles a negative sign bit (0x00800000),
        // but for block targets we assume they are always positive.

        Hash256::from_bytes(target)
    }

    /// Convert a 256-bit target back to compact bits.
    pub fn target_to_bits(target: &Hash256) -> u32 {
        let bytes = target.as_bytes();

        // Find the most significant byte
        let mut n_size = 32;
        while n_size > 0 && bytes[n_size - 1] == 0 {
            n_size -= 1;
        }

        if n_size == 0 {
            return 0;
        }

        let mut exponent = n_size as u32;
        let mut mantissa: u32;

        if exponent >= 3 {
            mantissa = (bytes[exponent as usize - 1] as u32) << 16
                | (bytes[exponent as usize - 2] as u32) << 8
                | (bytes[exponent as usize - 3] as u32);
        } else if exponent == 2 {
            mantissa = (bytes[1] as u32) << 16 | (bytes[0] as u32) << 8;
        } else {
            mantissa = (bytes[0] as u32) << 16;
        }

        // If the 24th bit is set, we must shift right and increment exponent
        if (mantissa & 0x0080_0000) != 0 {
            mantissa >>= 8;
            exponent += 1;
        }

        (exponent << 24) | mantissa
    }

    /// True if hash <= target (valid proof-of-work).
    ///
    /// Bitcoin Core: `CheckProofOfWork()` in `src/pow.cpp`
    pub fn meets_target(&self) -> bool {
        Hash256::from_bytes(*self.block_hash().as_bytes()) <= self.target()
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
// Block
// ---------------------------------------------------------------------------

/// A full Bitcoin block (header + transactions).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    pub fn new(header: BlockHeader, transactions: Vec<Transaction>) -> Self {
        Self {
            header,
            transactions,
        }
    }

    /// Calculate the Merkle Root of all transactions in this block.
    ///
    /// Bitcoin Core: `ComputeMerkleRoot()` in `src/consensus/merkle.cpp`.
    /// Block weight in weight units.
    ///
    /// Bitcoin Core: `GetBlockWeight()` — base size counted three extra times
    /// plus the full size, so base bytes cost four weight units each and
    /// witness bytes cost one. That discount is what lets a segwit block carry
    /// more data than the old one-megabyte limit while staying bounded.
    pub fn weight(&self) -> u64 {
        let total = crate::wire::encode::serialize(self).len() as u64;
        let witness: u64 = self
            .transactions
            .iter()
            .map(|tx| tx.witness_serialized_size() as u64)
            .sum();
        let base = total.saturating_sub(witness);
        base * 3 + total
    }

    pub fn compute_merkle_root(&self) -> Hash256 {
        if self.transactions.is_empty() {
            return Hash256::ZERO;
        }

        // 1. Initial level: TXIDs
        let mut hashes: Vec<Hash256> = self
            .transactions
            .iter()
            .map(|tx| Hash256::from_bytes(*tx.txid().as_bytes()))
            .collect();

        // 2. Iteratively compute levels until one root hash remains
        while hashes.len() > 1 {
            // If odd number of hashes, duplicate the last one (Bitcoin rule)
            if hashes.len() % 2 != 0 {
                hashes.push(hashes[hashes.len() - 1]);
            }

            let mut next_level = Vec::with_capacity(hashes.len() / 2);
            for chunk in hashes.chunks(2) {
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(chunk[0].as_bytes());
                combined[32..].copy_from_slice(chunk[1].as_bytes());
                next_level.push(Hash256::hash(&combined));
            }
            hashes = next_level;
        }

        hashes[0]
    }
}

impl BitcoinEncode for Block {
    fn encode(&self, enc: Encoder) -> Encoder {
        enc.encode_field(&self.header)
            .encode_field(&VarList(&self.transactions))
    }
}

impl BitcoinDecode for Block {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        let (header, dec) = dec.decode_field::<BlockHeader>("Block::header")?;
        let (transactions, dec) = dec.read_var_list::<Transaction>("Block::transactions")?;
        Ok((
            Self {
                header,
                transactions,
            },
            dec,
        ))
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
    #[error("block time {block_time} must be greater than median time past {median_time_past}")]
    TimestampBelowMedianTimePast {
        block_time: u32,
        median_time_past: u32,
    },

    /// `bits` does not match the required difficulty at this height.
    /// Bitcoin Core: `GetNextWorkRequired()` comparison
    #[error("wrong difficulty at height {height}: got {actual:#010x}, expected {expected:#010x}")]
    WrongDifficulty {
        height: u32,
        actual: u32,
        expected: u32,
    },
}

// ---------------------------------------------------------------------------
// Block index
// ---------------------------------------------------------------------------

/// Metadata about a block in the chain.
///
/// Bitcoin Core: `CBlockIndex` in `src/chain.h`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockIndex {
    pub header: BlockHeader,
    pub height: BlockHeight,
    pub chain_work: Hash256,
    pub file_pos: Option<FlatFilePos>,
    pub undo_pos: Option<FlatFilePos>,
}

impl BitcoinEncode for BlockIndex {
    fn encode(&self, enc: Encoder) -> Encoder {
        enc.encode_field(&self.header)
            .encode_field(&self.height)
            .encode_field(&self.chain_work)
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
        let (chain_work, dec) = dec.decode_field::<Hash256>("BlockIndex::chain_work")?;

        let (has_pos, dec) = dec.decode_field::<bool>("BlockIndex::has_pos")?;
        let (pos, dec) = dec.decode_field::<FlatFilePos>("BlockIndex::pos")?;
        let file_pos = if has_pos { Some(pos) } else { None };

        let (has_undo, dec) = dec.decode_field::<bool>("BlockIndex::has_undo")?;
        let (undo, dec) = dec.decode_field::<FlatFilePos>("BlockIndex::undo")?;
        let undo_pos = if has_undo { Some(undo) } else { None };

        Ok((
            BlockIndex {
                header,
                height,
                chain_work,
                file_pos,
                undo_pos,
            },
            dec,
        ))
    }
}

// ---------------------------------------------------------------------------
// Block locator
// ---------------------------------------------------------------------------

/// Build a Bitcoin block locator for `tip_height`.
///
/// A locator is the list of block hashes a peer uses to find the last block we
/// have in common. It starts dense (the ten most recent blocks) and then steps
/// back exponentially, always ending at genesis. Sending only the tip hash is
/// not a valid locator: if the peer does not have that exact block it falls
/// back to genesis and replies from height 1, which makes both reorg recovery
/// and resumed sync impossible.
///
/// `hash_at_height` resolves a height on the caller's active header chain.
/// Heights that cannot be resolved are skipped, so a partially populated index
/// still yields a usable (if sparser) locator.
///
/// Bitcoin Core: `GetLocator()` / `CChain::GetLocator()` in `src/chain.cpp`.
pub fn build_block_locator<F>(tip_height: u32, hash_at_height: F) -> Vec<BlockHash>
where
    F: Fn(u32) -> Option<BlockHash>,
{
    let mut have = Vec::with_capacity(32);
    let mut step: u32 = 1;
    let mut height = tip_height;

    loop {
        if let Some(hash) = hash_at_height(height) {
            have.push(hash);
        }

        if height == 0 {
            break;
        }

        // Bitcoin Core: `std::max(height - step, 0)`, then widen the step once
        // more than 10 entries have been collected. The step is doubled *after*
        // the next height is computed, which is what puts the first widened gap
        // at entry 12 rather than entry 11.
        height = height.saturating_sub(step);
        if have.len() > 10 {
            step = step.saturating_mul(2);
        }
    }

    have
}

#[cfg(test)]
mod locator_tests {
    use super::*;

    fn hash_for(height: u32) -> BlockHash {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&height.to_le_bytes());
        BlockHash::from_bytes(bytes)
    }

    fn heights_of(locator: &[BlockHash]) -> Vec<u32> {
        locator
            .iter()
            .map(|hash| u32::from_le_bytes(hash.as_bytes()[..4].try_into().unwrap()))
            .collect()
    }

    #[test]
    fn genesis_only_chain_yields_single_entry() {
        let locator = build_block_locator(0, |h| Some(hash_for(h)));
        assert_eq!(heights_of(&locator), vec![0]);
    }

    #[test]
    fn short_chain_is_dense_and_ends_at_genesis() {
        let locator = build_block_locator(5, |h| Some(hash_for(h)));
        assert_eq!(heights_of(&locator), vec![5, 4, 3, 2, 1, 0]);
    }

    #[test]
    fn long_chain_steps_back_exponentially_and_ends_at_genesis() {
        let locator = build_block_locator(100_000, |h| Some(hash_for(h)));
        let heights = heights_of(&locator);

        // First eleven entries are consecutive (Core widens only after len > 10).
        assert_eq!(
            heights[..11],
            [
                100_000, 99_999, 99_998, 99_997, 99_996, 99_995, 99_994, 99_993, 99_992, 99_991,
                99_990
            ]
        );
        // Then the gap doubles each step.
        assert_eq!(heights[11], 99_989);
        assert_eq!(heights[12], 99_987);
        assert_eq!(heights[13], 99_983);
        assert_eq!(heights[14], 99_975);

        assert_eq!(*heights.last().unwrap(), 0, "locator must reach genesis");
        assert!(
            heights.windows(2).all(|w| w[0] > w[1]),
            "must be strictly descending"
        );
        // Exponential back-off keeps the locator small even for long chains.
        assert!(heights.len() < 40, "locator too large: {}", heights.len());
    }

    #[test]
    fn unresolvable_heights_are_skipped_without_breaking_the_walk() {
        // Simulate a header index with a hole around height 90.
        let locator = build_block_locator(100, |h| if h == 90 { None } else { Some(hash_for(h)) });
        let heights = heights_of(&locator);

        assert!(!heights.contains(&90));
        assert_eq!(heights[0], 100);
        assert_eq!(*heights.last().unwrap(), 0);
    }
}
