use crate::types::block::BlockHeader;
use crate::types::hash::{BlockHash, Hash256};
use crate::types::magic::Magic;
use std::collections::HashMap;

/// Types of Base58 prefixes used in Bitcoin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Base58Type {
    PubKeyAddress,
    ScriptAddress,
    SecretKey,
    ExtPublicKey,
    ExtSecretKey,
}

/// Network-specific constants and consensus parameters.
///
/// Bitcoin Core: `Consensus::Params` in `src/consensus/params.h`
#[derive(Debug, Clone)]
pub struct ConsensusParams {
    /// Height-based activation heights
    pub bip34_height: u32,
    pub bip65_height: u32,
    pub bip66_height: u32,
    pub segwit_height: u32,

    /// Proof of work limits
    pub pow_limit: Hash256,
    pub pow_target_spacing: u64,
    pub pow_target_timespan: u64,
    pub pow_no_retargeting: bool,
    pub f_pow_allow_min_difficulty_blocks: bool,

    /// Progress and validation safeguards
    pub n_subsidy_halving_interval: u32,
    pub n_minimum_chain_work: Hash256,
    pub default_assume_valid: BlockHash,

    /// Signet-specific parameters (BIP 325)
    pub signet_blocks: bool,
    pub signet_challenge: Vec<u8>,
}

/// Orchestrates chain parameters.
///
/// Bitcoin Core: `CChainParams` in `src/chainparams.h`
#[derive(Debug, Clone)]
pub struct ChainParams {
    /// Bitcoin Core: `CChainParams::MessageStart()` / `pchMessageStart`.
    pub magic: Magic,
    pub genesis_header: BlockHeader,
    pub consensus: ConsensusParams,

    /// Network identity and address parameters
    pub default_port: u16,
    pub bech32_hrp: &'static str,
    pub base58_prefixes: HashMap<Base58Type, Vec<u8>>,
    pub dns_seeds: Vec<&'static str>,
}

impl ChainParams {
    /// Return the P2P message-start bytes for this chain.
    ///
    /// Bitcoin Core: `CChainParams::MessageStart()`.
    pub const fn message_start(&self) -> Magic {
        self.magic
    }

    pub fn genesis_hash(&self) -> BlockHash {
        self.genesis_header.block_hash()
    }
}
