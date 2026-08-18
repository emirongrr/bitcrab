//! Taproot primitives (BIP 341 / BIP 342).
//!
//! Bitcoin Core: `src/script/interpreter.cpp` (`VerifyTaprootCommitment`,
//! `ComputeTapleafHash`, `ComputeTaprootMerkleRoot`) and `src/script/script.h`.
//!
//! A taproot output commits to a public key `Q = P + t·G`, where `P` is an
//! internal key and `t = TapTweak(P || merkle_root)` binds a merkle tree of
//! alternative spending scripts. Spending either proves knowledge of the key
//! behind `Q` (key path), or reveals one leaf of the tree plus a merkle proof
//! (script path).

use bitcrab_common::types::hash::sha256;
use secp256k1::{Parity, Scalar, Secp256k1, Verification, XOnlyPublicKey};

/// Bitcoin Core: `TAPROOT_LEAF_MASK` — the leaf version occupies all bits of
/// the control byte except the low one, which carries the output key's parity.
pub const TAPROOT_LEAF_MASK: u8 = 0xfe;
/// Bitcoin Core: `TAPROOT_LEAF_TAPSCRIPT` — the only leaf version with defined
/// semantics; everything else is reserved for future soft forks.
pub const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc0;
/// Bitcoin Core: `TAPROOT_CONTROL_BASE_SIZE` — control byte plus internal key.
pub const TAPROOT_CONTROL_BASE_SIZE: usize = 33;
/// Bitcoin Core: `TAPROOT_CONTROL_NODE_SIZE`.
pub const TAPROOT_CONTROL_NODE_SIZE: usize = 32;
/// Bitcoin Core: `TAPROOT_CONTROL_MAX_NODE_COUNT` — a 2^128-leaf tree.
pub const TAPROOT_CONTROL_MAX_NODE_COUNT: usize = 128;
/// Bitcoin Core: `TAPROOT_CONTROL_MAX_SIZE`.
pub const TAPROOT_CONTROL_MAX_SIZE: usize =
    TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * TAPROOT_CONTROL_MAX_NODE_COUNT;
/// Bitcoin Core: `WITNESS_V1_TAPROOT_SIZE`.
pub const WITNESS_V1_TAPROOT_SIZE: usize = 32;
/// Bitcoin Core: `ANNEX_TAG` — a final witness item starting with this byte is
/// the annex, which is stripped before the spend is interpreted.
pub const ANNEX_TAG: u8 = 0x50;

/// Bitcoin Core: `VALIDATION_WEIGHT_OFFSET`.
pub const VALIDATION_WEIGHT_OFFSET: i64 = 50;
/// Bitcoin Core: `VALIDATION_WEIGHT_PER_SIGOP_PASSED`.
pub const VALIDATION_WEIGHT_PER_SIGOP_PASSED: i64 = 50;

/// BIP 340 tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || data)`.
///
/// The doubled tag hash makes collisions across different tags infeasible even
/// though every tag shares one hash function.
pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = sha256(tag.as_bytes());
    let mut buffer = Vec::with_capacity(64 + data.len());
    buffer.extend_from_slice(&tag_hash);
    buffer.extend_from_slice(&tag_hash);
    buffer.extend_from_slice(data);
    sha256(&buffer)
}

/// Per-input state that taproot signature hashing needs.
///
/// Bitcoin Core: `ScriptExecutionData` in `src/script/interpreter.h`.
#[derive(Debug, Clone, Default)]
pub struct ScriptExecutionData {
    /// Hash of the leaf script being executed (script path only).
    pub tapleaf_hash: Option<[u8; 32]>,
    /// `SHA256(compact_size(annex) || annex)` when an annex is present.
    pub annex_hash: Option<[u8; 32]>,
    /// Opcode position of the last executed `OP_CODESEPARATOR`.
    ///
    /// Bitcoin Core uses `0xffffffff` to mean "none", and that sentinel is
    /// committed to by the signature, so it must round-trip exactly.
    pub codeseparator_pos: u32,
    /// Remaining signature-checking budget (tapscript only).
    pub validation_weight_left: i64,
}

impl ScriptExecutionData {
    pub fn new() -> Self {
        Self {
            codeseparator_pos: u32::MAX,
            ..Default::default()
        }
    }
}

/// A parsed taproot control block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlBlock {
    pub leaf_version: u8,
    pub output_key_parity: Parity,
    pub internal_key: [u8; 32],
    /// Merkle path from the leaf to the root, 32 bytes per level.
    pub merkle_path: Vec<[u8; 32]>,
}

/// Parse the control block from the last witness item of a script-path spend.
///
/// Bitcoin Core: the size checks in `VerifyWitnessProgram` plus
/// `VerifyTaprootCommitment`.
pub fn parse_control_block(control: &[u8]) -> Option<ControlBlock> {
    if control.len() < TAPROOT_CONTROL_BASE_SIZE
        || control.len() > TAPROOT_CONTROL_MAX_SIZE
        || (control.len() - TAPROOT_CONTROL_BASE_SIZE) % TAPROOT_CONTROL_NODE_SIZE != 0
    {
        return None;
    }

    let leaf_version = control[0] & TAPROOT_LEAF_MASK;
    let output_key_parity = if control[0] & 1 == 1 {
        Parity::Odd
    } else {
        Parity::Even
    };

    let internal_key: [u8; 32] = control[1..33].try_into().ok()?;

    let merkle_path = control[TAPROOT_CONTROL_BASE_SIZE..]
        .chunks_exact(TAPROOT_CONTROL_NODE_SIZE)
        .map(|node| {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(node);
            bytes
        })
        .collect();

    Some(ControlBlock {
        leaf_version,
        output_key_parity,
        internal_key,
        merkle_path,
    })
}

/// Hash of a single leaf of the taproot script tree.
///
/// Bitcoin Core: `ComputeTapleafHash()`.
pub fn compute_tapleaf_hash(leaf_version: u8, script: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(1 + 9 + script.len());
    data.push(leaf_version);
    write_compact_size(&mut data, script.len() as u64);
    data.extend_from_slice(script);
    tagged_hash("TapLeaf", &data)
}

/// Fold a merkle path from a leaf up to the tree root.
///
/// Bitcoin Core: `ComputeTaprootMerkleRoot()`. Siblings are ordered
/// lexicographically before hashing, so the tree has no notion of left and
/// right and the proof carries no direction bits.
pub fn compute_taproot_merkle_root(control: &ControlBlock, tapleaf_hash: [u8; 32]) -> [u8; 32] {
    let mut node = tapleaf_hash;
    for sibling in &control.merkle_path {
        let mut data = [0u8; 64];
        if node <= *sibling {
            data[..32].copy_from_slice(&node);
            data[32..].copy_from_slice(sibling);
        } else {
            data[..32].copy_from_slice(sibling);
            data[32..].copy_from_slice(&node);
        }
        node = tagged_hash("TapBranch", &data);
    }
    node
}

/// Check that the revealed script really is committed to by the output key.
///
/// Bitcoin Core: `VerifyTaprootCommitment()`.
///
/// Verifies `Q == P + TapTweak(P || merkle_root)·G`, with `Q` the 32-byte
/// witness program and `P` the internal key from the control block.
pub fn verify_taproot_commitment<C: Verification>(
    secp: &Secp256k1<C>,
    control: &ControlBlock,
    program: &[u8],
    tapleaf_hash: [u8; 32],
) -> bool {
    let Ok(output_key) = XOnlyPublicKey::from_slice(program) else {
        return false;
    };
    let Ok(internal_key) = XOnlyPublicKey::from_slice(&control.internal_key) else {
        return false;
    };

    let merkle_root = compute_taproot_merkle_root(control, tapleaf_hash);

    let mut tweak_data = Vec::with_capacity(64);
    tweak_data.extend_from_slice(&control.internal_key);
    tweak_data.extend_from_slice(&merkle_root);
    let tweak = tagged_hash("TapTweak", &tweak_data);

    let Ok(tweak) = Scalar::from_be_bytes(tweak) else {
        return false;
    };

    internal_key.tweak_add_check(secp, &output_key, control.output_key_parity, tweak)
}

/// True for opcodes BIP 342 reserves as `OP_SUCCESSx`.
///
/// Bitcoin Core: `IsOpSuccess()`. If any appears anywhere in a tapscript — even
/// inside a branch that is never taken — the script succeeds immediately. This
/// is the upgrade hook that lets future soft forks define new behaviour without
/// invalidating old nodes.
pub const fn is_op_success(opcode: u8) -> bool {
    opcode == 80
        || opcode == 98
        || (opcode >= 126 && opcode <= 129)
        || (opcode >= 131 && opcode <= 134)
        || (opcode >= 137 && opcode <= 138)
        || (opcode >= 141 && opcode <= 142)
        || (opcode >= 149 && opcode <= 153)
        || (opcode >= 187 && opcode <= 254)
}

/// Write a Bitcoin compact-size integer.
pub fn write_compact_size(out: &mut Vec<u8>, value: u64) {
    if value < 0xfd {
        out.push(value as u8);
    } else if value <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&value.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tagged_hash_matches_the_bip340_definition() {
        // The definition is SHA256(SHA256(tag) || SHA256(tag) || msg); compute
        // it the long way and compare.
        let tag_hash = sha256(b"TapLeaf");
        let mut expected_input = Vec::new();
        expected_input.extend_from_slice(&tag_hash);
        expected_input.extend_from_slice(&tag_hash);
        expected_input.extend_from_slice(b"payload");
        assert_eq!(tagged_hash("TapLeaf", b"payload"), sha256(&expected_input));
    }

    #[test]
    fn different_tags_give_different_digests() {
        assert_ne!(tagged_hash("TapLeaf", b"x"), tagged_hash("TapBranch", b"x"));
        assert_ne!(tagged_hash("TapTweak", b"x"), tagged_hash("TapLeaf", b"x"));
    }

    #[test]
    fn control_block_sizes_are_validated() {
        // Base size alone: valid, zero-length merkle path.
        let control = vec![0xc0; TAPROOT_CONTROL_BASE_SIZE];
        let parsed = parse_control_block(&control).unwrap();
        assert_eq!(parsed.leaf_version, 0xc0);
        assert_eq!(parsed.merkle_path.len(), 0);

        // One node.
        let control = vec![0xc0; TAPROOT_CONTROL_BASE_SIZE + 32];
        assert_eq!(parse_control_block(&control).unwrap().merkle_path.len(), 1);

        // Too short, and a length that is not base + 32n.
        assert!(parse_control_block(&[0xc0; 32]).is_none());
        assert!(parse_control_block(&[0xc0; TAPROOT_CONTROL_BASE_SIZE + 5]).is_none());
        // Past the 128-node maximum.
        assert!(parse_control_block(&vec![0xc0; TAPROOT_CONTROL_MAX_SIZE + 32]).is_none());
        // Exactly at the maximum is fine.
        assert!(parse_control_block(&vec![0xc0; TAPROOT_CONTROL_MAX_SIZE]).is_some());
    }

    #[test]
    fn control_byte_splits_into_version_and_parity() {
        let mut control = vec![0u8; TAPROOT_CONTROL_BASE_SIZE];

        control[0] = 0xc0;
        let parsed = parse_control_block(&control).unwrap();
        assert_eq!(parsed.leaf_version, 0xc0);
        assert_eq!(parsed.output_key_parity, Parity::Even);

        control[0] = 0xc1;
        let parsed = parse_control_block(&control).unwrap();
        assert_eq!(
            parsed.leaf_version, 0xc0,
            "parity bit is not part of the version"
        );
        assert_eq!(parsed.output_key_parity, Parity::Odd);
    }

    #[test]
    fn merkle_root_sorts_siblings_lexicographically() {
        // Swapping which node is "ours" and which is the sibling must give the
        // same root, because the pair is sorted before hashing.
        let low = [0x01u8; 32];
        let high = [0xfeu8; 32];

        let a = ControlBlock {
            leaf_version: 0xc0,
            output_key_parity: Parity::Even,
            internal_key: [0; 32],
            merkle_path: vec![high],
        };
        let b = ControlBlock {
            leaf_version: 0xc0,
            output_key_parity: Parity::Even,
            internal_key: [0; 32],
            merkle_path: vec![low],
        };

        assert_eq!(
            compute_taproot_merkle_root(&a, low),
            compute_taproot_merkle_root(&b, high)
        );
    }

    #[test]
    fn empty_merkle_path_leaves_the_leaf_hash_untouched() {
        let control = ControlBlock {
            leaf_version: 0xc0,
            output_key_parity: Parity::Even,
            internal_key: [0; 32],
            merkle_path: Vec::new(),
        };
        let leaf = [0x77u8; 32];
        assert_eq!(compute_taproot_merkle_root(&control, leaf), leaf);
    }

    #[test]
    fn tapleaf_hash_commits_to_version_and_script() {
        let script = vec![0x51];
        let a = compute_tapleaf_hash(0xc0, &script);
        let b = compute_tapleaf_hash(0xc2, &script);
        let c = compute_tapleaf_hash(0xc0, &[0x52]);
        assert_ne!(a, b, "leaf version must be committed to");
        assert_ne!(a, c, "script must be committed to");
    }

    #[test]
    fn op_success_table_matches_bip342() {
        for opcode in [
            80u8, 98, 126, 129, 131, 134, 137, 138, 141, 142, 149, 153, 187, 254,
        ] {
            assert!(is_op_success(opcode), "{} must be OP_SUCCESS", opcode);
        }
        // Ordinary opcodes and the ones BIP 342 keeps defined.
        for opcode in [
            0u8, 81, 99, 118, 130, 135, 139, 143, 148, 154, 172, 186, 255,
        ] {
            assert!(!is_op_success(opcode), "{} must not be OP_SUCCESS", opcode);
        }
    }

    #[test]
    fn compact_size_boundaries() {
        let mut out = Vec::new();
        write_compact_size(&mut out, 0xfc);
        assert_eq!(out, vec![0xfc]);

        out.clear();
        write_compact_size(&mut out, 0xfd);
        assert_eq!(out, vec![0xfd, 0xfd, 0x00]);

        out.clear();
        write_compact_size(&mut out, 0x1_0000);
        assert_eq!(out, vec![0xfe, 0x00, 0x00, 0x01, 0x00]);
    }
}
