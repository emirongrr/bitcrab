use crate::types::genesis::Genesis;
use crate::types::hash::{BlockHash, Hash256};
use crate::types::magic::Magic;
use crate::types::params::{Base58Type, ChainParams, ConsensusParams};
use std::collections::HashMap;

pub fn testnet3_params() -> ChainParams {
    let genesis = Genesis::testnet3().build();

    let mut base58_prefixes = HashMap::new();
    base58_prefixes.insert(Base58Type::PubKeyAddress, vec![111]);
    base58_prefixes.insert(Base58Type::ScriptAddress, vec![196]);
    base58_prefixes.insert(Base58Type::SecretKey, vec![239]);
    base58_prefixes.insert(Base58Type::ExtPublicKey, vec![0x04, 0x35, 0x87, 0xCF]);
    base58_prefixes.insert(Base58Type::ExtSecretKey, vec![0x04, 0x35, 0x83, 0x94]);

    let consensus = ConsensusParams {
        bip34_height: 21111,
        bip65_height: 581885,
        bip66_height: 330776,
        segwit_height: 834624,
        pow_limit: Hash256::from_hex_be(
            "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
        pow_target_spacing: 600,
        pow_target_timespan: 14 * 24 * 60 * 60,
        pow_no_retargeting: false,
        f_pow_allow_min_difficulty_blocks: true,
        n_subsidy_halving_interval: 210000,
        n_minimum_chain_work: Hash256::from_hex_be(
            "0000000000000000000000000000000000000000000017dde1c649f3708d14b6",
        ),
        default_assume_valid: BlockHash::from_hex_be(
            "000000007a61e4230b28ac5cb6b5e5a0130de37ac1faf2f8987d2fa6505b67f4",
        ),
        signet_blocks: false,
        signet_challenge: vec![],
    };

    ChainParams {
        magic: Magic::TESTNET3, // Ensure Magic has TESTNET3
        genesis_header: genesis.header,
        consensus,
        default_port: 18333,
        bech32_hrp: "tb",
        base58_prefixes,
        dns_seeds: vec![
            "testnet-seed.bitcoin.jonasschnelli.ch",
            "seed.tbtc.petertodd.net",
            "seed.testnet.bitcoin.sprovoost.nl",
            "testnet-seed.bluematt.me",
            "seed.testnet.achownodes.xyz",
        ],
    }
}
