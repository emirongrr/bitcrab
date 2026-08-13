use crate::types::genesis::Genesis;
use crate::types::hash::{BlockHash, Hash256};
use crate::types::magic::Magic;
use crate::types::params::{Base58Type, ChainParams, ConsensusParams};
use std::collections::HashMap;

pub fn signet_params() -> ChainParams {
    let genesis = Genesis::signet().build();

    let mut base58_prefixes = HashMap::new();
    base58_prefixes.insert(Base58Type::PubKeyAddress, vec![111]);
    base58_prefixes.insert(Base58Type::ScriptAddress, vec![196]);
    base58_prefixes.insert(Base58Type::SecretKey, vec![239]);
    base58_prefixes.insert(Base58Type::ExtPublicKey, vec![0x04, 0x35, 0x87, 0xCF]);
    base58_prefixes.insert(Base58Type::ExtSecretKey, vec![0x04, 0x35, 0x83, 0x94]);

    // Official Default Signet Challenge
    let challenge_hex = "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae";
    let challenge = hex::decode(challenge_hex).unwrap();

    let magic = Magic::SIGNET;

    let consensus = ConsensusParams {
        bip34_height: 1,
        bip65_height: 1,
        bip66_height: 1,
        segwit_height: 1,
        pow_limit: Hash256::from_hex_be(
            "00000377ae000000000000000000000000000000000000000000000000000000",
        ),
        pow_target_spacing: 600,
        pow_target_timespan: 14 * 24 * 60 * 60,
        pow_no_retargeting: false,
        f_pow_allow_min_difficulty_blocks: false,
        n_subsidy_halving_interval: 210000,
        n_minimum_chain_work: Hash256::from_hex_be(
            "00000000000000000000000000000000000000000000000000000b463ea0a4b8",
        ),
        default_assume_valid: BlockHash::from_hex_be(
            "00000008414aab61092ef93f1aacc54cf9e9f16af29ddad493b908a01ff5c329",
        ),
        signet_blocks: true,
        signet_challenge: challenge,
    };

    ChainParams {
        magic,
        genesis_header: genesis.header,
        consensus,
        default_port: 38333,
        bech32_hrp: "tb",
        base58_prefixes,
        // Bitcoin Core: src/kernel/chainparams.cpp (default Signet).
        dns_seeds: vec!["seed.signet.bitcoin.sprovoost.nl"],
    }
}
