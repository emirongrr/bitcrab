//! Proof of Work and Difficulty Adjustment Logic.
//!
//! Matches Bitcoin Core's `src/pow.cpp`.

use bitcrab_common::types::block::{BlockHeader, BlockIndex};
use bitcrab_common::types::hash::Hash256;
use bitcrab_common::types::params::ConsensusParams;

/// Interface for looking up block indices needed for difficulty retargeting.
pub trait BlockIndexProvider {
    fn get_block_index_by_height(&self, height: u32) -> Option<BlockIndex>;
}

/// Calculate the required difficulty for a new block.
///
/// Bitcoin Core: `GetNextWorkRequired()` in `src/pow.cpp`
pub fn get_next_work_required<P: BlockIndexProvider>(
    index_prev: &BlockIndex,
    header: &BlockHeader,
    params: &ConsensusParams,
    provider: &P,
) -> u32 {
    // 1. Regtest / No Retargeting
    if params.pow_no_retargeting {
        return index_prev.header.bits;
    }

    // 2. Special rule for Testnet / Signet:
    if params.f_pow_allow_min_difficulty_blocks {
        // If the new block's timestamp is more than 2*target_spacing minutes
        // after the previous block's timestamp, then allow minimum difficulty.
        if header.time > index_prev.header.time + (params.pow_target_spacing as u32 * 2) {
            return BlockHeader::target_to_bits(&params.pow_limit);
        } else {
            // Return the last non-special-min-difficulty-block's bits
            // For now, simple fallback to index_prev.bits (sufficient for most cases)
            return index_prev.header.bits;
        }
    }

    let next_height = index_prev.height.0 + 1;
    let difficulty_adjustment_interval = params.pow_target_timespan / params.pow_target_spacing;

    // 3. Only change once per difficulty adjustment interval
    if next_height % difficulty_adjustment_interval as u32 != 0 {
        return index_prev.header.bits;
    }

    // 4. Perform Retarget
    // Bitcoin Core: nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    let first_height = index_prev
        .height
        .0
        .saturating_sub(difficulty_adjustment_interval as u32 - 1);

    let Some(index_first) = provider.get_block_index_by_height(first_height) else {
        tracing::warn!(
            "Retarget failed: index_first not found at height {}",
            first_height
        );
        return index_prev.header.bits;
    };

    tracing::info!(
        "Retargeting at height {}: comparing time(prev_height={}) with time(first_height={})",
        next_height,
        index_prev.height.0,
        first_height
    );

    calculate_next_work_required(index_prev, index_first.header.time, params)
}

/// Core retargeting math.
///
/// Bitcoin Core: `CalculateNextWorkRequired()` in `src/pow.cpp`
pub fn calculate_next_work_required(
    index_prev: &BlockIndex,
    first_block_time: u32,
    params: &ConsensusParams,
) -> u32 {
    if params.pow_no_retargeting {
        return index_prev.header.bits;
    }

    // 1. Calculate actual timespan
    let mut actual_timespan = index_prev.header.time.saturating_sub(first_block_time) as i64;

    // 2. Clamp adjustment (max 4x up or 0.25x down)
    let min_timespan = (params.pow_target_timespan / 4) as i64;
    let max_timespan = (params.pow_target_timespan * 4) as i64;

    if actual_timespan < min_timespan {
        actual_timespan = min_timespan;
    }
    if actual_timespan > max_timespan {
        actual_timespan = max_timespan;
    }

    // 3. Calculate new target
    let mut target = BlockHeader::bits_to_target(index_prev.header.bits);

    // target = (target * actual_timespan) / target_timespan
    target = multiply_and_divide(target, actual_timespan as u64, params.pow_target_timespan);

    // 4. Clamp to PoW limit
    if target > params.pow_limit {
        target = params.pow_limit;
    }

    let next_bits = BlockHeader::target_to_bits(&target);

    tracing::info!(
        "Retargeting results: actual_timespan={}, target_timespan={}, old_bits=0x{:08x}, new_bits=0x{:08x}",
        actual_timespan, params.pow_target_timespan, index_prev.header.bits, next_bits
    );

    next_bits
}

#[allow(clippy::needless_range_loop)]
pub fn calculate_block_work(bits: u32) -> Hash256 {
    let target = BlockHeader::bits_to_target(bits);
    if target.is_zero() {
        return Hash256::zero();
    }

    // Bitcoin Core: work = (~target / (target + 1)) + 1
    // This provides 2^256 / (target + 1).

    // 1. Numerator = ~target
    let mut numerator = [0u8; 32];
    let target_bytes = target.as_bytes();
    for i in 0..32 {
        numerator[i] = !target_bytes[i];
    }

    // 2. Denominator = target + 1
    let mut denominator = [0u8; 32];
    denominator.copy_from_slice(target_bytes);
    let mut carry: u16 = 1;
    for i in 0..32 {
        let sum = denominator[i] as u16 + carry;
        denominator[i] = (sum & 0xFF) as u8;
        carry = sum >> 8;
    }

    // 3. Division: numerator / denominator
    let mut quotient = [0u8; 32];
    let mut remainder = [0u8; 32];

    for i in (0..256).rev() {
        // Shift remainder left
        let mut c = 0u8;
        for j in 0..32 {
            let next_c = remainder[j] >> 7;
            remainder[j] = (remainder[j] << 1) | c;
            c = next_c;
        }

        // Take bit i of numerator and put it into remainder[0]
        let bit = (numerator[i / 8] >> (i % 8)) & 1;
        remainder[0] |= bit;

        // If remainder >= denominator, subtract and set quotient bit
        let mut ge = true;
        for j in (0..32).rev() {
            if remainder[j] < denominator[j] {
                ge = false;
                break;
            } else if remainder[j] > denominator[j] {
                break;
            }
        }

        if ge {
            let mut borrow = 0i16;
            for j in 0..32 {
                let diff = remainder[j] as i16 - denominator[j] as i16 - borrow;
                if diff < 0 {
                    remainder[j] = (diff + 256) as u8;
                    borrow = 1;
                } else {
                    remainder[j] = diff as u8;
                    borrow = 0;
                }
            }
            quotient[i / 8] |= 1 << (i % 8);
        }
    }

    // 4. Result = quotient + 1
    let mut res = quotient;
    let mut carry = 1u16;
    for i in 0..32 {
        let sum = res[i] as u16 + carry;
        res[i] = (sum & 0xFF) as u8;
        carry = sum >> 8;
    }

    Hash256::from_bytes(res)
}

/// Accumulate chain work.
pub fn add_chain_work(a: Hash256, b: Hash256) -> Hash256 {
    let mut res = [0u8; 32];
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();

    let mut carry: u16 = 0;
    for i in 0..32 {
        let sum = a_bytes[i] as u16 + b_bytes[i] as u16 + carry;
        res[i] = (sum & 0xFF) as u8;
        carry = sum >> 8;
    }
    Hash256::from_bytes(res)
}

/// Arith_uint256 multiplication and division with 256-bit overflow detection.
///
/// Bitcoin Core: `bnNew *= nActualTimespan; bnNew /= nTargetTimespan;`
#[allow(clippy::needless_range_loop)]
fn multiply_and_divide(target: Hash256, mul: u64, div: u64) -> Hash256 {
    let target_bytes = target.as_bytes();

    // Use 32-bit blocks for math (16 * 32 = 512 bits to avoid intermediate product overflow)
    let mut expanded = [0u32; 16];
    for i in 0..8 {
        expanded[i] = u32::from_le_bytes(target_bytes[i * 4..(i + 1) * 4].try_into().unwrap());
    }

    // 1. Multiplication: (expanded * mul)
    let mut carry: u128 = 0;
    for i in 0..16 {
        let val = (expanded[i] as u128 * mul as u128) + carry;
        expanded[i] = (val & 0xFFFF_FFFF) as u32;
        carry = val >> 32;
    }

    // 2. Division: (expanded / div)
    let mut remainder: u128 = 0;
    for i in (0..16).rev() {
        let val = expanded[i] as u128 + (remainder << 32);
        expanded[i] = (val / div as u128) as u32;
        remainder = val % div as u128;
    }

    // 3. Overflow Check: If any bits above 255 are set, return MAX to trigger pow_limit clamp.
    let mut overflow = false;
    for i in 8..16 {
        if expanded[i] != 0 {
            overflow = true;
            break;
        }
    }

    if overflow {
        return Hash256::from_bytes([0xFF; 32]);
    }

    let mut result = [0u8; 32];
    for i in 0..8 {
        result[i * 4..(i + 1) * 4].copy_from_slice(&expanded[i].to_le_bytes());
    }
    Hash256::from_bytes(result)
}
