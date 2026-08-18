//! Script verification flags.
//!
//! Mirrors the `SCRIPT_VERIFY_*` bits in Bitcoin Core
//! `src/script/interpreter.h`. The bit positions are part of the
//! `libbitcoinconsensus` ABI, so they must match exactly for the differential
//! tests to pass meaningful flag sets to both engines.

/// A set of `SCRIPT_VERIFY_*` bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VerifyFlags(pub u32);

impl VerifyFlags {
    pub const NONE: Self = Self(0);
    /// Evaluate P2SH subscripts (BIP 16).
    pub const P2SH: Self = Self(1 << 0);
    /// Enforce strict signature/pubkey encoding.
    pub const STRICTENC: Self = Self(1 << 1);
    /// Enforce strict DER (BIP 66).
    pub const DERSIG: Self = Self(1 << 2);
    /// Enforce low S values (BIP 62).
    pub const LOW_S: Self = Self(1 << 3);
    /// CHECKMULTISIG dummy must be an empty push (BIP 147).
    pub const NULLDUMMY: Self = Self(1 << 4);
    /// scriptSig must contain only pushes.
    pub const SIGPUSHONLY: Self = Self(1 << 5);
    /// Pushes must use the minimal possible encoding.
    pub const MINIMALDATA: Self = Self(1 << 6);
    /// Reject unknown NOPs.
    pub const DISCOURAGE_UPGRADABLE_NOPS: Self = Self(1 << 7);
    /// Require exactly one stack element on completion.
    pub const CLEANSTACK: Self = Self(1 << 8);
    /// Enable OP_CHECKLOCKTIMEVERIFY (BIP 65).
    pub const CHECKLOCKTIMEVERIFY: Self = Self(1 << 9);
    /// Enable OP_CHECKSEQUENCEVERIFY (BIP 112).
    pub const CHECKSEQUENCEVERIFY: Self = Self(1 << 10);
    /// Enable segregated witness (BIP 141).
    pub const WITNESS: Self = Self(1 << 11);
    /// Reject unknown witness versions.
    pub const DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: Self = Self(1 << 12);
    /// OP_IF/OP_NOTIF arguments must be exactly empty or `0x01`.
    pub const MINIMALIF: Self = Self(1 << 13);
    /// Failed signature checks must supply an empty signature (BIP 146).
    pub const NULLFAIL: Self = Self(1 << 14);
    /// Witness pubkeys must be compressed.
    pub const WITNESS_PUBKEYTYPE: Self = Self(1 << 15);
    /// scriptCode covered by a signature must not contain OP_CODESEPARATOR.
    pub const CONST_SCRIPTCODE: Self = Self(1 << 16);
    /// Enable taproot (BIP 341 / BIP 342).
    pub const TAPROOT: Self = Self(1 << 17);
    /// Reject reserved leaf versions in a taproot control block.
    pub const DISCOURAGE_UPGRADABLE_TAPROOT_VERSION: Self = Self(1 << 18);
    /// Reject `OP_SUCCESSx` in tapscript.
    pub const DISCOURAGE_OP_SUCCESS: Self = Self(1 << 19);
    /// Reject tapscript public keys of an as-yet-undefined size.
    pub const DISCOURAGE_UPGRADABLE_PUBKEYTYPE: Self = Self(1 << 20);

    /// The flag set Bitcoin Core applies to blocks once every deployed
    /// soft fork is active. This is what full validation of a modern chain
    /// (mainnet post-segwit, or signet at any height) uses.
    ///
    /// Bitcoin Core: the accumulated `SCRIPT_VERIFY_*` in `GetBlockScriptFlags()`
    /// for a chain with P2SH, DERSIG, CLTV, CSV, NULLDUMMY and segwit active.
    pub const CONSENSUS_SEGWIT: Self = Self(
        Self::P2SH.0
            | Self::DERSIG.0
            | Self::NULLDUMMY.0
            | Self::CHECKLOCKTIMEVERIFY.0
            | Self::CHECKSEQUENCEVERIFY.0
            | Self::WITNESS.0,
    );

    /// Every deployed soft fork, taproot included. This is what a modern
    /// mainnet or signet block is validated under.
    pub const CONSENSUS_TAPROOT: Self = Self(Self::CONSENSUS_SEGWIT.0 | Self::TAPROOT.0);

    pub const fn bits(self) -> u32 {
        self.0
    }

    /// True when every bit in `other` is set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl std::ops::BitOr for VerifyFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl std::ops::BitOrAssign for VerifyFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_positions_match_bitcoin_core() {
        // These constants are ABI with libbitcoinconsensus; a silent change here
        // would make every differential test compare different rule sets.
        assert_eq!(VerifyFlags::P2SH.bits(), 1);
        assert_eq!(VerifyFlags::DERSIG.bits(), 4);
        assert_eq!(VerifyFlags::NULLDUMMY.bits(), 16);
        assert_eq!(VerifyFlags::CHECKLOCKTIMEVERIFY.bits(), 512);
        assert_eq!(VerifyFlags::CHECKSEQUENCEVERIFY.bits(), 1024);
        assert_eq!(VerifyFlags::WITNESS.bits(), 2048);
        assert_eq!(VerifyFlags::TAPROOT.bits(), 1 << 17);
    }

    #[test]
    fn contains_is_a_subset_test() {
        let flags = VerifyFlags::P2SH | VerifyFlags::WITNESS;
        assert!(flags.contains(VerifyFlags::P2SH));
        assert!(flags.contains(VerifyFlags::WITNESS));
        assert!(!flags.contains(VerifyFlags::LOW_S));
        assert!(flags.contains(VerifyFlags::P2SH | VerifyFlags::WITNESS));
    }
}
