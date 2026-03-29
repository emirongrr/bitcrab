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

/// A non-negative Bitcoin amount in satoshis.
///
/// Always in `[0, MAX_MONEY]`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Debug)]
pub struct Amount(u64);

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_money_is_accepted() {
        assert!(Amount::from_sat(MAX_MONEY).is_ok());
    }

    #[test]
    fn one_above_max_is_rejected() {
        let err = Amount::from_sat(MAX_MONEY + 1).unwrap_err();
        assert!(matches!(err, AmountError::ExceedsMaxMoney(_)));
        assert!(err.to_string().contains("MAX_MONEY"));
    }

    #[test]
    fn checked_add_stops_at_max() {
        assert!(Amount::MAX.checked_add(Amount::from_sat(1).unwrap()).is_none());
    }

    #[test]
    fn checked_sub_no_underflow() {
        let a = Amount::from_sat(5).unwrap();
        let b = Amount::from_sat(10).unwrap();
        assert!(a.checked_sub(b).is_none());
    }

    #[test]
    fn display_one_bitcoin() {
        assert_eq!(Amount::ONE_BTC.to_string(), "1.00000000 BTC");
    }

    #[test]
    fn fee_pattern() {
        let inputs  = Amount::from_sat(100_000).unwrap();
        let outputs = Amount::from_sat(99_000).unwrap();
        let fee = inputs.checked_sub(outputs).unwrap();
        assert_eq!(fee.to_sat(), 1_000);
    }
}