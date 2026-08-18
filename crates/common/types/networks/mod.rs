pub mod mainnet;
pub mod regtest;
pub mod signet;
pub mod testnet3;

pub use mainnet::mainnet_params;
pub use regtest::regtest_params;
pub use signet::signet_params;
pub use testnet3::testnet3_params;

use crate::types::params::ChainParams;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Represents the active Bitcoin chain type.
///
/// Matches Bitcoin Core's `ChainType` enum in `src/kernel/chainparams.h`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainType {
    #[default]
    Mainnet,
    Testnet3,
    Signet,
    Regtest,
}

impl ChainType {
    /// Returns the ChainParams for the network.
    pub fn chain_params(&self) -> ChainParams {
        match self {
            ChainType::Mainnet => mainnet_params(),
            ChainType::Testnet3 => testnet3_params(),
            ChainType::Signet => signet_params(),
            ChainType::Regtest => regtest_params(),
        }
    }

    /// Returns the network-specific subdirectory name for the datadir.
    pub fn datadir_suffix(&self) -> Option<&'static str> {
        match self {
            ChainType::Mainnet => None,
            ChainType::Testnet3 => Some("testnet3"),
            ChainType::Signet => Some("signet"),
            ChainType::Regtest => Some("regtest"),
        }
    }

    /// All available chain types.
    pub fn all() -> &'static [ChainType] {
        &[
            ChainType::Mainnet,
            ChainType::Testnet3,
            ChainType::Signet,
            ChainType::Regtest,
        ]
    }
}

impl fmt::Display for ChainType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ChainType::Mainnet => "mainnet",
            ChainType::Testnet3 => "testnet3",
            ChainType::Signet => "signet",
            ChainType::Regtest => "regtest",
        };
        write!(f, "{}", s)
    }
}

impl From<&str> for ChainType {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "mainnet" => ChainType::Mainnet,
            "testnet" | "testnet3" => ChainType::Testnet3,
            "signet" => ChainType::Signet,
            "regtest" => ChainType::Regtest,
            _ => ChainType::Mainnet,
        }
    }
}
