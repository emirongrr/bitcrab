//! Selectable script-consensus engines.
//!
//! `Native` is Bitcrab's own implementation (`bitcrab-script`).
//! `CoreReference` is `libbitcoinconsensus`, kept as a differential oracle so
//! the native engine can be checked against the reference rule for rule.

use crate::validation::ValidationError;
use bitcrab_common::types::{coin::Coin, transaction::Transaction};
use bitcrab_script::{
    checker::{PrecomputedTransactionData, TransactionSignatureChecker},
    verify_script, VerifyFlags,
};
use secp256k1::Secp256k1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusEngineKind {
    Native,
    CoreReference,
}

#[derive(Debug, Clone, Copy)]
pub struct ConsensusEngine {
    kind: ConsensusEngineKind,
    flags: VerifyFlags,
}

impl ConsensusEngine {
    pub const fn new(kind: ConsensusEngineKind) -> Self {
        Self {
            kind,
            flags: VerifyFlags::CONSENSUS_TAPROOT,
        }
    }

    /// Override the script verification flags.
    ///
    /// Bitcoin Core derives these per block from which soft forks are active
    /// (`GetBlockScriptFlags`). The default here is the fully-activated set.
    pub const fn with_flags(mut self, flags: VerifyFlags) -> Self {
        self.flags = flags;
        self
    }

    pub const fn kind(self) -> ConsensusEngineKind {
        self.kind
    }

    pub const fn flags(self) -> VerifyFlags {
        self.flags
    }

    pub fn verify_transaction(
        self,
        tx: &Transaction,
        spent_coins: &[Coin],
    ) -> Result<(), ValidationError> {
        match self.kind {
            ConsensusEngineKind::Native => verify_native(tx, spent_coins, self.flags),
            ConsensusEngineKind::CoreReference => {
                verify_core_reference(tx, spent_coins, self.flags)
            }
        }
    }
}

/// Verify every input with the native engine.
///
/// The BIP 143 and BIP 341 midstates are computed once and shared across
/// inputs; doing it per input would make segwit and taproot validation
/// quadratic in the number of inputs.
fn verify_native(
    tx: &Transaction,
    spent_coins: &[Coin],
    flags: VerifyFlags,
) -> Result<(), ValidationError> {
    if spent_coins.len() != tx.inputs.len() {
        return Err(ValidationError::ScriptFailure);
    }

    // Taproot commits to every spent output, not just the one being verified.
    let spent_outputs: Vec<_> = spent_coins.iter().map(|coin| coin.output.clone()).collect();

    let secp = Secp256k1::verification_only();
    let cache = PrecomputedTransactionData::new(tx, &spent_outputs);

    for (index, input) in tx.inputs.iter().enumerate() {
        let coin = &spent_coins[index];

        let checker = TransactionSignatureChecker::new(tx, index, &spent_outputs, &secp)
            .with_cache(cache.clone());

        verify_script(
            input.script_sig.as_bytes(),
            coin.output.script_pubkey.as_bytes(),
            &input.witness,
            flags,
            &checker,
        )
        .map_err(|error| ValidationError::ScriptError { index, error })?;
    }

    Ok(())
}

fn verify_core_reference(
    tx: &Transaction,
    spent_coins: &[Coin],
    flags: VerifyFlags,
) -> Result<(), ValidationError> {
    #[cfg(not(feature = "core-reference"))]
    {
        let _ = (tx, spent_coins, flags);
        Err(ValidationError::ReferenceEngineUnavailable)
    }

    #[cfg(feature = "core-reference")]
    {
        let raw_tx = bitcrab_common::wire::encode::serialize(tx);
        let spent_outputs = spent_coins
            .iter()
            .map(|coin| bitcoinconsensus::Utxo {
                script_pubkey: coin.output.script_pubkey.as_bytes().as_ptr(),
                script_pubkey_len: coin.output.script_pubkey.len() as u32,
                value: coin.output.value.to_sat() as i64,
            })
            .collect::<Vec<_>>();

        for (index, coin) in spent_coins.iter().enumerate() {
            bitcoinconsensus::verify_with_flags(
                coin.output.script_pubkey.as_bytes(),
                coin.output.value.to_sat(),
                &raw_tx,
                Some(&spent_outputs),
                index,
                flags.bits(),
            )
            .map_err(|_| ValidationError::ScriptError {
                index,
                error: bitcrab_script::ScriptError::UnknownError,
            })?;
        }
        Ok(())
    }
}
