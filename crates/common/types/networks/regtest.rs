use crate::types::genesis::Genesis;
use crate::types::hash::{BlockHash, Hash256};
use crate::types::magic::Magic;
use crate::types::params::{Base58Type, ChainParams, ConsensusParams};
use std::collections::HashMap;

pub fn regtest_params() -> ChainParams {
    let genesis = Genesis::regtest().build();

    let mut base58_prefixes = HashMap::new();
    base58_prefixes.insert(Base58Type::PubKeyAddress, vec![111]);
    base58_prefixes.insert(Base58Type::ScriptAddress, vec![196]);
    base58_prefixes.insert(Base58Type::SecretKey, vec![239]);
    base58_prefixes.insert(Base58Type::ExtPublicKey, vec![0x04, 0x35, 0x87, 0xCF]);
    base58_prefixes.insert(Base58Type::ExtSecretKey, vec![0x04, 0x35, 0x83, 0x94]);

    let consensus = ConsensusParams {
        bip34_height: 100,
        bip65_height: 1351,
        bip66_height: 1251,
        segwit_height: 0,
        pow_limit: Hash256::from_hex_be(
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
        pow_target_spacing: 600,
        pow_target_timespan: 14 * 24 * 60 * 60,
        pow_no_retargeting: true,
        f_pow_allow_min_difficulty_blocks: true,
        n_subsidy_halving_interval: 150,
        n_minimum_chain_work: Hash256::from_hex_be(
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
        default_assume_valid: BlockHash::from_hex_be(
            "06226e46111a0b59caaf126043eb5b79c60f48e789a30595d9715734b6dee15c",
        ),
        signet_blocks: false,
        signet_challenge: vec![],
    };

    ChainParams {
        magic: Magic::REGTEST,
        genesis_header: genesis.header,
        consensus,
        default_port: 18444,
        bech32_hrp: "bcrt",
        base58_prefixes,
        dns_seeds: vec![],
    }
}
