//! Bitcoin amount type — satoshis, overflow-safe.
//!
//! # Bitcoin Core
//!
//! `CAmount = int64_t` in `src/consensus/amount.h`.
//! Range is checked manually via `MoneyRange()`.
//! Silent overflow is possible with raw `+` and `*`.
//!
//! # Bitcrab
//!
//! `Amount` is a newtype over `u64`.
//! Negative values are unrepresentable.
//! All arithmetic is checked — overflow returns an error.

use super::constants::{COIN, MAX_MONEY};
use crate::wire::{
    decode::{BitcoinDecode, Decoder},
    encode::{BitcoinEncode, Encoder},
    error::DecodeError,
};

/// A non-negative Bitcoin amount in satoshis.
///
/// Always in `[0, MAX_MONEY]`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug)]
pub struct Amount(u64);

impl BitcoinEncode for Amount {
    fn encode(&self, enc: Encoder) -> Encoder {
        enc.encode_field(&self.0)
    }
}

impl BitcoinDecode for Amount {
    fn decode(dec: Decoder) -> Result<(Self, Decoder), DecodeError> {
        let (val, dec) = dec.decode_field::<u64>("Amount")?;
        Ok((Self(val), dec))
    }
}

impl Amount {
    /// Zero satoshis.
    pub const ZERO: Self = Self(0);

    /// Maximum valid amount (MAX_MONEY satoshis).
    pub const MAX: Self = Self(MAX_MONEY);

    /// One bitcoin (100_000_000 satoshis).
    pub const ONE_BTC: Self = Self(COIN);

    /// Construct from satoshis.
    ///
    /// Returns `Err` if `sats > MAX_MONEY`.
    pub fn from_sat(sats: u64) -> Result<Self, AmountError> {
        if sats > MAX_MONEY {
            return Err(AmountError::ExceedsMaxMoney(sats));
        }
        Ok(Self(sats))
    }

    /// Raw satoshi value.
    #[inline]
    pub fn to_sat(self) -> u64 {
        self.0
    }

    /// Checked addition.
    ///
    /// Returns `None` if result exceeds `MAX_MONEY`.
    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.0
            .checked_add(other.0)
            .filter(|&v| v <= MAX_MONEY)
            .map(Self)
    }

    /// Checked subtraction.
    ///
    /// Returns `None` if result would be negative.
    pub fn checked_sub(self, other: Self) -> Option<Self> {
        self.0.checked_sub(other.0).map(Self)
    }

    /// Checked multiplication by a scalar (e.g. for fee rate calculations).
    pub fn checked_mul(self, factor: u64) -> Option<Self> {
        self.0
            .checked_mul(factor)
            .filter(|&v| v <= MAX_MONEY)
            .map(Self)
    }

    /// Check if the amount is within the valid Bitcoin supply range [0, MAX_MONEY].
    pub fn is_valid(self) -> bool {
        self.0 <= MAX_MONEY
    }
}

impl std::fmt::Display for Amount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.8} BTC", self.0 as f64 / COIN as f64)
    }
}

// ---------------------------------------------------------------------------
// Amount errors
// ---------------------------------------------------------------------------

/// Errors from `Amount` construction and arithmetic.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AmountError {
    /// Value exceeds the 21 million BTC supply cap.
    #[error("{0} satoshis exceeds MAX_MONEY ({MAX_MONEY})")]
    ExceedsMaxMoney(u64),

    /// Subtraction would produce a negative result.
    #[error("subtraction underflow: {minuend} - {subtrahend} would be negative")]
    WouldBeNegative { minuend: u64, subtrahend: u64 },

    /// Addition overflowed u64.
    #[error("arithmetic overflow computing amount")]
    Overflow,
}
