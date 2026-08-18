//! BIP 325 signet block solution validation.
//!
//! Signet blocks carry no meaningful proof of work; their authority comes from
//! a signature over the block committed inside the coinbase witness commitment.
//! Validating that signature is the *only* thing separating a real signet chain
//! from one anybody can mint, so this module reproduces Bitcoin Core's
//! `src/signet.cpp` rather than approximating it.
//!
//! The construction, per BIP 325:
//!
//! 1. Locate the coinbase's witness commitment output.
//! 2. Extract the `ecc7daa2`-tagged section from it — that is the solution —
//!    and blank the section back down to the bare tag.
//! 3. Recompute the block's merkle root with that modified coinbase in place
//!    (the "modified merkle root"); this is what the signature covers.
//! 4. Build two virtual transactions, `to_spend` and `to_sign`, that bind the
//!    block header fields and the modified merkle root.
//! 5. Verify the solution's scriptSig/witness against the network's challenge
//!    script as if it were spending `to_spend`'s output.

use bitcrab_common::types::{
    amount::Amount,
    block::Block,
    hash::{Hash256, Txid},
    script::ScriptBuf,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
};
use bitcrab_common::ChainParams;
use bitcrab_script::{TransactionSignatureChecker, VerifyFlags};
use secp256k1::Secp256k1;
use thiserror::Error;

/// Tag identifying the signet solution inside the witness commitment.
///
/// Bitcoin Core: `SIGNET_HEADER` in `src/signet.cpp`.
pub const SIGNET_HEADER: [u8; 4] = [0xec, 0xc7, 0xda, 0xa2];

/// Minimum size of a BIP 141 witness commitment output script.
///
/// Bitcoin Core: `MINIMUM_WITNESS_COMMITMENT` in `src/validation.h`.
const MINIMUM_WITNESS_COMMITMENT: usize = 38;

/// Bitcoin Core: `WITNESS_COMMITMENT_HEADER` — `OP_RETURN OP_PUSHBYTES_36 aa21a9ed`.
const WITNESS_COMMITMENT_PREFIX: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SignetError {
    #[error("signet challenge is empty in consensus params")]
    ChallengeMissing,
    #[error("block has no coinbase transaction")]
    NoCoinbase,
    #[error("coinbase has no witness commitment output")]
    MissingWitnessCommitment,
    #[error("malformed signet solution: {0}")]
    MalformedSolution(String),
    #[error("signet challenge requires script features Bitcrab cannot verify natively: {0}")]
    UnsupportedChallenge(String),
    #[error("signet solution script failed: {0}")]
    ScriptFailed(bitcrab_script::ScriptError),
}

/// The two virtual transactions BIP 325 derives from a signet block.
///
/// Bitcoin Core: `SignetTxs` in `src/signet.h`.
#[derive(Debug, Clone)]
pub struct SignetTxs {
    pub to_spend: Transaction,
    pub to_sign: Transaction,
}

impl SignetTxs {
    /// Derive `to_spend` / `to_sign` for `block` under `challenge`.
    ///
    /// Bitcoin Core: `SignetTxs::SignetTxs()` in `src/signet.cpp`.
    pub fn new(block: &Block, challenge: &[u8]) -> Result<Self, SignetError> {
        let coinbase = block.transactions.first().ok_or(SignetError::NoCoinbase)?;
        if !coinbase.is_coinbase() {
            return Err(SignetError::NoCoinbase);
        }

        // Core requires a witness commitment; without one there is nowhere for
        // the solution to live and the block is rejected outright.
        let cidx =
            get_witness_commitment_index(coinbase).ok_or(SignetError::MissingWitnessCommitment)?;

        let mut modified_coinbase = coinbase.clone();
        let (solution, modified_commitment) = fetch_and_clear_commitment_section(
            &SIGNET_HEADER,
            modified_coinbase.outputs[cidx].script_pubkey.as_bytes(),
        );
        modified_coinbase.outputs[cidx].script_pubkey = ScriptBuf::from_bytes(modified_commitment);

        // A missing section is not an error: it is how a trivial challenge such
        // as OP_TRUE is expressed. A present-but-malformed one is an error.
        let (script_sig, witness) = match solution {
            Some(bytes) => parse_signet_solution(&bytes)?,
            None => (Vec::new(), Vec::new()),
        };

        let signet_merkle = compute_modified_merkle_root(block, &modified_coinbase);

        // Bitcoin Core serialises nVersion, hashPrevBlock, the *modified* merkle
        // root and nTime — deliberately excluding nBits and nNonce so the signer
        // does not have to commit to the (meaningless) proof of work.
        let mut block_data = Vec::with_capacity(72);
        block_data.extend_from_slice(&block.header.version.to_le_bytes());
        block_data.extend_from_slice(block.header.prev_hash.as_bytes());
        block_data.extend_from_slice(signet_merkle.as_bytes());
        block_data.extend_from_slice(&block.header.time.to_le_bytes());

        let mut to_spend_script_sig = vec![0x00]; // OP_0
        push_data(&mut to_spend_script_sig, &block_data);

        let to_spend = Transaction {
            version: 0,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::ZERO,
                    // Bitcoin Core: default-constructed COutPoint uses NULL_INDEX.
                    vout: u32::MAX,
                },
                script_sig: ScriptBuf::from_bytes(to_spend_script_sig),
                sequence: 0,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(challenge.to_vec()),
            }],
            lock_time: 0,
        };

        let to_sign = Transaction {
            version: 0,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: to_spend.txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::from_bytes(script_sig),
                sequence: 0,
                witness,
            }],
            outputs: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(vec![0x6a]), // OP_RETURN
            }],
            lock_time: 0,
        };

        Ok(Self { to_spend, to_sign })
    }
}

/// Verify a signet block's solution against the network challenge.
///
/// Bitcoin Core: `CheckSignetBlockSolution()` in `src/signet.cpp`.
///
/// This is a *contextless* check: it needs only the block and the chain params,
/// which is why Core calls it from `CheckBlock` and why it must run before any
/// UTXO state is touched.
pub fn check_signet_block_solution(block: &Block, params: &ChainParams) -> Result<(), SignetError> {
    // Bitcoin Core compares against hashGenesisBlock: the genesis block carries
    // no solution and is trusted by definition.
    if block.header.block_hash() == params.genesis_hash() {
        return Ok(());
    }

    let challenge = &params.consensus.signet_challenge;
    if challenge.is_empty() {
        return Err(SignetError::ChallengeMissing);
    }

    let txs = SignetTxs::new(block, challenge)?;
    verify_solution_script(&txs, challenge)
}

/// Run the challenge script against the solution.
///
/// Bitcoin Core: `VerifyScript(scriptSig, challenge, &witness, BLOCK_SCRIPT_VERIFY_FLAGS, ...)`.
///
/// Bitcoin Core uses `BLOCK_SCRIPT_VERIFY_FLAGS` here: P2SH, DERSIG, NULLDUMMY
/// and WITNESS. The native engine now supports all of them, so the default
/// signet challenge (a bare 1-of-2 multisig) and P2SH/P2WSH challenges are all
/// evaluated for real. Taproot challenges are not yet supported by the engine
/// and are reported as such rather than silently accepted.
fn verify_solution_script(txs: &SignetTxs, challenge: &[u8]) -> Result<(), SignetError> {
    // An unknown witness version is anyone-can-spend to this engine, so
    // evaluating it would return success for *any* block. Refuse up front.
    if is_unsupported_challenge(challenge) {
        return Err(SignetError::UnsupportedChallenge(
            "challenge is a v1+ witness program (taproot)".into(),
        ));
    }

    let input = &txs.to_sign.inputs[0];

    // Bitcoin Core: BLOCK_SCRIPT_VERIFY_FLAGS in src/signet.cpp.
    let flags = VerifyFlags::P2SH
        | VerifyFlags::DERSIG
        | VerifyFlags::NULLDUMMY
        | VerifyFlags::WITNESS
        | VerifyFlags::TAPROOT;

    let challenge_script = ScriptBuf::from_bytes(challenge.to_vec());
    let secp = Secp256k1::verification_only();
    // to_spend has exactly one output — the challenge itself, holding zero
    // satoshis — and that is the output to_sign spends.
    let spent_outputs = txs.to_spend.outputs.clone();
    let checker = TransactionSignatureChecker::new(&txs.to_sign, 0, &spent_outputs, &secp);

    match bitcrab_script::verify_script(
        input.script_sig.as_bytes(),
        challenge_script.as_bytes(),
        &input.witness,
        flags,
        &checker,
    ) {
        Ok(()) => Ok(()),
        Err(error) => Err(SignetError::ScriptFailed(error)),
    }
}

/// True for challenge forms the native engine cannot actually verify.
///
/// The engine treats an unknown witness version as anyone-can-spend, which for
/// a *block* challenge would mean accepting every block. Taproot (v1, 32-byte
/// program) is implemented, so only versions beyond it — and malformed v1
/// programs, which fall through the same upgrade path — are refused here.
fn is_unsupported_challenge(challenge: &[u8]) -> bool {
    match bitcrab_script::script_ops::parse_witness_program(challenge) {
        Some(program) if program.version == 0 => false,
        Some(program) if program.version == 1 => {
            program.program.len() != bitcrab_script::taproot::WITNESS_V1_TAPROOT_SIZE
        }
        Some(_) => true,
        None => false,
    }
}

/// Merkle root of `block` with its coinbase replaced by `modified_coinbase`.
///
/// Bitcoin Core: `ComputeModifiedMerkleRoot()` in `src/signet.cpp`.
fn compute_modified_merkle_root(block: &Block, modified_coinbase: &Transaction) -> Hash256 {
    let mut hashes: Vec<Hash256> = Vec::with_capacity(block.transactions.len());
    hashes.push(Hash256::from_bytes(*modified_coinbase.txid().as_bytes()));
    for tx in block.transactions.iter().skip(1) {
        hashes.push(Hash256::from_bytes(*tx.txid().as_bytes()));
    }
    merkle_root(hashes)
}

/// Standard Bitcoin merkle root over an ordered hash list.
pub(crate) fn merkle_root(mut hashes: Vec<Hash256>) -> Hash256 {
    if hashes.is_empty() {
        return Hash256::ZERO;
    }

    while hashes.len() > 1 {
        if hashes.len() % 2 != 0 {
            hashes.push(hashes[hashes.len() - 1]);
        }
        let mut next = Vec::with_capacity(hashes.len() / 2);
        for pair in hashes.chunks(2) {
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(pair[0].as_bytes());
            combined[32..].copy_from_slice(pair[1].as_bytes());
            next.push(Hash256::hash(&combined));
        }
        hashes = next;
    }

    hashes[0]
}

/// Index of the coinbase output holding the BIP 141 witness commitment.
///
/// Shared with `validation`, which needs it to check the commitment itself.
///
/// Bitcoin Core: `GetWitnessCommitmentIndex()` in `src/validation.cpp` — the
/// *last* matching output wins.
pub fn get_witness_commitment_index(coinbase: &Transaction) -> Option<usize> {
    coinbase
        .outputs
        .iter()
        .enumerate()
        .rev()
        .find_map(|(i, output)| {
            let script = output.script_pubkey.as_bytes();
            (script.len() >= MINIMUM_WITNESS_COMMITMENT && script[..6] == WITNESS_COMMITMENT_PREFIX)
                .then_some(i)
        })
}

/// Split the `header`-tagged section out of a witness commitment script.
///
/// Returns the section payload (without the tag) and the script rewritten with
/// that section collapsed back to a bare push of the tag — which is what the
/// signature was produced over.
///
/// Bitcoin Core: `FetchAndClearCommitmentSection()` in `src/signet.cpp`.
pub fn fetch_and_clear_commitment_section(
    header: &[u8; 4],
    script: &[u8],
) -> (Option<Vec<u8>>, Vec<u8>) {
    let mut pos = 0;
    let mut section = None;
    let mut modified = Vec::with_capacity(script.len());

    while pos < script.len() {
        let opcode = script[pos];
        pos += 1;

        // Determine the push payload for this opcode, if any.
        let (size_len, len) = if opcode == 0 {
            (0, 0)
        } else if opcode <= 75 {
            (0, opcode as usize)
        } else if (0x4c..=0x4e).contains(&opcode) {
            let size_len = match opcode {
                0x4c => 1,
                0x4d => 2,
                _ => 4,
            };
            if pos + size_len > script.len() {
                break;
            }
            let len = match size_len {
                1 => script[pos] as usize,
                2 => u16::from_le_bytes(script[pos..pos + 2].try_into().unwrap()) as usize,
                _ => u32::from_le_bytes(script[pos..pos + 4].try_into().unwrap()) as usize,
            };
            (size_len, len)
        } else {
            // Not a push: copy verbatim.
            modified.push(opcode);
            continue;
        };

        let data_start = pos + size_len;
        if data_start + len > script.len() {
            break;
        }
        let data = &script[data_start..data_start + len];

        if section.is_none() && len > header.len() && data.starts_with(header) {
            section = Some(data[header.len()..].to_vec());
            // Collapse to a minimal push of just the tag.
            modified.push(header.len() as u8);
            modified.extend_from_slice(header);
        } else {
            modified.push(opcode);
            modified.extend_from_slice(&script[pos..data_start]);
            modified.extend_from_slice(data);
        }

        pos = data_start + len;
    }

    (section, modified)
}

/// Decode a signet solution into `(scriptSig, witness stack)`.
///
/// Bitcoin Core deserialises these as a `CScript` followed by a
/// `std::vector<std::vector<uint8_t>>`; trailing bytes are a hard error.
fn parse_signet_solution(data: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>), SignetError> {
    use bitcrab_common::wire::decode::Decoder;

    let dec = Decoder::new(data);
    let (script_sig, dec) = dec
        .read_varbytes("signet_scriptSig")
        .map_err(|e| SignetError::MalformedSolution(format!("scriptSig: {}", e)))?;
    let (witness, dec) = dec
        .read_var_list::<Vec<u8>>("signet_witness")
        .map_err(|e| SignetError::MalformedSolution(format!("witness: {}", e)))?;
    if !dec.is_done() {
        return Err(SignetError::MalformedSolution(
            "extraneous data after solution".into(),
        ));
    }
    Ok((script_sig, witness))
}

/// Append a minimal-form data push to `script`.
fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    match data.len() {
        len if len <= 75 => script.push(len as u8),
        len if len <= 0xff => {
            script.push(0x4c);
            script.push(len as u8);
        }
        len if len <= 0xffff => {
            script.push(0x4d);
            script.extend_from_slice(&(len as u16).to_le_bytes());
        }
        len => {
            script.push(0x4e);
            script.extend_from_slice(&(len as u32).to_le_bytes());
        }
    }
    script.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcrab_common::types::block::BlockHeader;
    use bitcrab_common::types::hash::BlockHash;
    use bitcrab_common::wire::encode::{Encoder, VarBytes, VarInt};
    use secp256k1::{Message, Secp256k1, SecretKey};

    /// Deterministic 1-of-2 bare multisig challenge, the same shape as the
    /// public signet's `OP_1 <pk1> <pk2> OP_2 OP_CHECKMULTISIG`.
    fn challenge_and_key() -> (Vec<u8>, SecretKey) {
        let secp = Secp256k1::new();
        let signing_key = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let other_key = SecretKey::from_slice(&[0x22; 32]).unwrap();

        let pk1 = signing_key.public_key(&secp).serialize();
        let pk2 = other_key.public_key(&secp).serialize();

        let mut challenge = vec![0x51]; // OP_1
        challenge.push(pk1.len() as u8);
        challenge.extend_from_slice(&pk1);
        challenge.push(pk2.len() as u8);
        challenge.extend_from_slice(&pk2);
        challenge.push(0x52); // OP_2
        challenge.push(0xae); // OP_CHECKMULTISIG

        (challenge, signing_key)
    }

    /// Build a coinbase whose commitment output optionally carries a tagged
    /// signet section.
    fn coinbase_with_commitment(signet_section: Option<&[u8]>) -> Transaction {
        // OP_RETURN <36 bytes: aa21a9ed || witness root>
        let mut commitment = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        commitment.extend_from_slice(&[0x77; 32]);

        if let Some(section) = signet_section {
            let mut tagged = SIGNET_HEADER.to_vec();
            tagged.extend_from_slice(section);
            push_data(&mut commitment, &tagged);
        }

        Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::ZERO,
                    vout: u32::MAX,
                },
                script_sig: ScriptBuf::from_bytes(vec![0x02, 0x10, 0x00]),
                sequence: 0xffff_ffff,
                witness: vec![vec![0u8; 32]],
            }],
            outputs: vec![
                TxOut {
                    value: Amount::from_sat(5_000_000_000).unwrap(),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                },
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: ScriptBuf::from_bytes(commitment),
                },
            ],
            lock_time: 0,
        }
    }

    fn block_with(coinbase: Transaction) -> Block {
        let mut block = Block {
            header: BlockHeader {
                version: 0x2000_0000,
                prev_hash: BlockHash::from_bytes([0xab; 32]),
                merkle_root: Hash256::ZERO,
                time: 1_600_000_000,
                bits: 0x1e03_77ae,
                nonce: 42,
            },
            transactions: vec![coinbase],
        };
        block.header.merkle_root = block.compute_merkle_root();
        block
    }

    /// Serialise a solution the way Core does: CScript, then witness stack.
    fn encode_solution(script_sig: &[u8], witness: &[Vec<u8>]) -> Vec<u8> {
        let mut enc = Encoder::new().encode_field(&VarBytes(script_sig));
        enc = enc.encode_field(&VarInt(witness.len() as u64));
        for item in witness {
            enc = enc.encode_field(&VarBytes(item));
        }
        enc.finish()
    }

    /// Sign `block` under the 1-of-2 challenge, the way a signet miner does.
    fn sign_block(block: &mut Block, challenge: &[u8], key: &SecretKey) {
        // The digest is taken over the coinbase with the section blanked, so a
        // placeholder of the same shape yields the same digest as the final
        // block. This is exactly why BIP 325 blanks the section.
        let placeholder = encode_solution(&[], &[]);
        *block = block_with(coinbase_with_commitment(Some(&placeholder)));

        let txs = SignetTxs::new(block, challenge).expect("virtual txs");
        let challenge_script = ScriptBuf::from_bytes(challenge.to_vec());
        let sighash = txs.to_sign.signature_hash(0, &challenge_script, 1);

        let secp = Secp256k1::new();
        let sig = secp.sign_ecdsa(&Message::from_digest(sighash), key);
        let mut sig_bytes = sig.serialize_der().to_vec();
        sig_bytes.push(0x01); // SIGHASH_ALL

        // Bare multisig scriptSig: OP_0 (NULLDUMMY) then the signature.
        let mut script_sig = vec![0x00];
        push_data(&mut script_sig, &sig_bytes);

        let solution = encode_solution(&script_sig, &[]);
        *block = block_with(coinbase_with_commitment(Some(&solution)));
    }

    #[test]
    fn commitment_section_round_trips_and_is_blanked() {
        let payload = b"solution-bytes".to_vec();
        let mut tagged = SIGNET_HEADER.to_vec();
        tagged.extend_from_slice(&payload);
        let mut script = vec![0x6a];
        push_data(&mut script, &tagged);

        let (section, modified) = fetch_and_clear_commitment_section(&SIGNET_HEADER, &script);
        assert_eq!(section.as_deref(), Some(payload.as_slice()));
        // Blanked form is OP_RETURN followed by a bare push of the 4-byte tag.
        assert_eq!(modified, vec![0x6a, 0x04, 0xec, 0xc7, 0xda, 0xa2]);
    }

    #[test]
    fn untagged_commitment_is_left_untouched() {
        let script = vec![0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef];
        let (section, modified) = fetch_and_clear_commitment_section(&SIGNET_HEADER, &script);
        assert_eq!(section, None);
        assert_eq!(modified, script);
    }

    #[test]
    fn correctly_signed_block_is_accepted() {
        let (challenge, key) = challenge_and_key();
        let mut block = block_with(coinbase_with_commitment(None));
        sign_block(&mut block, &challenge, &key);

        let txs = SignetTxs::new(&block, &challenge).expect("virtual txs");
        assert_eq!(
            verify_solution_script(&txs, &challenge),
            Ok(()),
            "a block signed by a challenge key must verify"
        );
    }

    #[test]
    fn tampering_with_the_header_invalidates_the_solution() {
        let (challenge, key) = challenge_and_key();
        let mut block = block_with(coinbase_with_commitment(None));
        sign_block(&mut block, &challenge, &key);

        // nTime is covered by the signed block_data.
        block.header.time += 1;
        let txs = SignetTxs::new(&block, &challenge).expect("virtual txs");
        assert!(matches!(
            verify_solution_script(&txs, &challenge),
            Err(SignetError::ScriptFailed(_))
        ));
    }

    #[test]
    fn a_block_signed_by_a_foreign_key_is_rejected() {
        let (challenge, _) = challenge_and_key();
        let foreign = SecretKey::from_slice(&[0x33; 32]).unwrap();

        let mut block = block_with(coinbase_with_commitment(None));
        sign_block(&mut block, &challenge, &foreign);

        let txs = SignetTxs::new(&block, &challenge).expect("virtual txs");
        assert!(
            matches!(
                verify_solution_script(&txs, &challenge),
                Err(SignetError::ScriptFailed(_))
            ),
            "a signature from a non-challenge key must not pass"
        );
    }

    #[test]
    fn a_block_with_no_solution_is_rejected() {
        // The case the previous structural-only check let through.
        let (challenge, _) = challenge_and_key();
        let block = block_with(coinbase_with_commitment(None));

        let txs = SignetTxs::new(&block, &challenge).expect("virtual txs");
        assert!(matches!(
            verify_solution_script(&txs, &challenge),
            Err(SignetError::ScriptFailed(_))
        ));
    }

    #[test]
    fn a_coinbase_without_witness_commitment_is_rejected() {
        let (challenge, _) = challenge_and_key();
        let mut coinbase = coinbase_with_commitment(None);
        coinbase.outputs.remove(1);
        let block = block_with(coinbase);

        assert_eq!(
            SignetTxs::new(&block, &challenge).err(),
            Some(SignetError::MissingWitnessCommitment)
        );
    }

    #[test]
    fn a_malformed_solution_is_rejected() {
        let (challenge, _) = challenge_and_key();
        // Valid encoding followed by junk: Core treats trailing bytes as fatal.
        let mut solution = encode_solution(&[0x00], &[]);
        solution.push(0xff);
        let block = block_with(coinbase_with_commitment(Some(&solution)));

        assert!(matches!(
            SignetTxs::new(&block, &challenge),
            Err(SignetError::MalformedSolution(_))
        ));
    }

    #[test]
    fn a_witness_v0_challenge_is_evaluated_not_skipped() {
        // P2WSH-style challenge: OP_0 <32 bytes>. The native engine supports
        // witness v0, so this must be really evaluated — and rejected, since
        // the solution carries no witness matching the program.
        let mut challenge = vec![0x00, 0x20];
        challenge.extend_from_slice(&[0x55; 32]);
        let solution = encode_solution(&[], &[]);
        let block = block_with(coinbase_with_commitment(Some(&solution)));

        let txs = SignetTxs::new(&block, &challenge).expect("virtual txs");
        assert!(matches!(
            verify_solution_script(&txs, &challenge),
            Err(SignetError::ScriptFailed(_))
        ));
    }

    #[test]
    fn a_taproot_challenge_is_evaluated_not_skipped() {
        // A well-formed v1 program is now really verified, so a block with no
        // matching signature must be rejected rather than waved through.
        let mut challenge = vec![0x51, 0x20]; // OP_1 <32 bytes>
        challenge.extend_from_slice(&[0x66; 32]);
        let solution = encode_solution(&[], &[]);
        let block = block_with(coinbase_with_commitment(Some(&solution)));

        let txs = SignetTxs::new(&block, &challenge).expect("virtual txs");
        assert!(matches!(
            verify_solution_script(&txs, &challenge),
            Err(SignetError::ScriptFailed(_))
        ));
    }

    #[test]
    fn a_witness_v2_challenge_is_refused_rather_than_waved_through() {
        // v2+ is still anyone-can-spend to this engine; accepting it would make
        // every block valid.
        let mut challenge = vec![0x52, 0x20]; // OP_2 <32 bytes>
        challenge.extend_from_slice(&[0x77; 32]);
        let solution = encode_solution(&[], &[]);
        let block = block_with(coinbase_with_commitment(Some(&solution)));

        let txs = SignetTxs::new(&block, &challenge).expect("virtual txs");
        assert!(matches!(
            verify_solution_script(&txs, &challenge),
            Err(SignetError::UnsupportedChallenge(_))
        ));
    }

    #[test]
    fn trivial_op_true_challenge_needs_no_solution() {
        let challenge = vec![0x51]; // OP_TRUE
        let block = block_with(coinbase_with_commitment(None));
        let txs = SignetTxs::new(&block, &challenge).expect("virtual txs");
        assert_eq!(verify_solution_script(&txs, &challenge), Ok(()));
    }

    #[test]
    fn modified_merkle_root_differs_from_the_block_merkle_root() {
        // The signature covers the blanked coinbase, so the two roots must
        // diverge whenever a solution is present. If they matched, the solution
        // would be committing to itself and could never be verified.
        let (challenge, key) = challenge_and_key();
        let mut block = block_with(coinbase_with_commitment(None));
        sign_block(&mut block, &challenge, &key);

        let coinbase = &block.transactions[0];
        let cidx = get_witness_commitment_index(coinbase).unwrap();
        let mut modified = coinbase.clone();
        let (_, blanked) = fetch_and_clear_commitment_section(
            &SIGNET_HEADER,
            modified.outputs[cidx].script_pubkey.as_bytes(),
        );
        modified.outputs[cidx].script_pubkey = ScriptBuf::from_bytes(blanked);

        assert_ne!(
            compute_modified_merkle_root(&block, &modified),
            block.header.merkle_root
        );
        let _ = challenge;
    }
}
