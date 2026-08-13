use crate::types::genesis::Genesis;
use crate::types::hash::{BlockHash, Hash256};
use crate::types::magic::Magic;
use crate::types::params::{Base58Type, ChainParams, ConsensusParams};
use std::collections::HashMap;

pub fn mainnet_params() -> ChainParams {
    let genesis = Genesis::mainnet().build();

    let mut base58_prefixes = HashMap::new();
    base58_prefixes.insert(Base58Type::PubKeyAddress, vec![0]);
    base58_prefixes.insert(Base58Type::ScriptAddress, vec![5]);
    base58_prefixes.insert(Base58Type::SecretKey, vec![128]);
    base58_prefixes.insert(Base58Type::ExtPublicKey, vec![0x04, 0x88, 0xB2, 0x1E]);
    base58_prefixes.insert(Base58Type::ExtSecretKey, vec![0x04, 0x88, 0xAD, 0xE4]);

    let consensus = ConsensusParams {
        bip34_height: 227931,
        bip65_height: 388381,
        bip66_height: 363725,
        segwit_height: 481824,
        pow_limit: Hash256::from_hex_be(
            "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
        pow_target_spacing: 600,
        pow_target_timespan: 14 * 24 * 60 * 60,
        pow_no_retargeting: false,
        f_pow_allow_min_difficulty_blocks: false,
        n_subsidy_halving_interval: 210000,
        n_minimum_chain_work: Hash256::from_hex_be(
            "000000000000000000000000000000000000000017dde1c649f3708d14b6",
        ),
        default_assume_valid: BlockHash::from_hex_be(
            "000000000000000000035c3f0d31e71a5cb24c9ad35140bbdaed4af95ba3d52e",
        ),
        signet_blocks: false,
        signet_challenge: vec![],
    };

    ChainParams {
        magic: Magic::MAINNET,
        genesis_header: genesis.header,
        consensus,
        default_port: 8333,
        bech32_hrp: "bc",
        base58_prefixes,
        dns_seeds: vec![
            "seed.bitcoin.sipa.be",
            "dnsseed.bluematt.me",
            "dnsseed.bitcoin.dashjr-list.of.hetzner.de",
            "seed.bitcoinstats.com",
            "seed.bitcoin.jonasschnelli.ch",
            "seed.btc.petertodd.net",
        ],
    }
}
