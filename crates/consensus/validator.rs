//! Consensus Validation Engine.
//!
//! Implements the rules for validating Bitcoin transactions and blocks.
//! Matches Bitcoin Core's `src/consensus/tx_verify.cpp` and `src/validation.cpp`.

use bitcrab_common::types::amount::Amount;
use bitcrab_common::types::transaction::Transaction;
use thiserror::Error;

use bitcrab_common::types::undo::BlockUndo;
use bitcrab_script::interpreter::ScriptInterpreter;

use crate::coins_view::{CoinsView, CoinsViewCache};

/// Errors that can occur during consensus validation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("transaction has no inputs")]
    NoInputs,
    #[error("transaction has no outputs")]
    NoOutputs,
    #[error("transaction size exceeds limit")]
    TooLarge,
    #[error("output value exceeds maximum allowed")]
    AmountOutOfRange,
    #[error("total output value exceeds maximum allowed")]
    TotalAmountOutOfRange,
    #[error("input already spent or non-existent: {0:?}")]
    InputMissingOrSpent(bitcrab_common::types::transaction::OutPoint),
    #[error("input value sum less than output value sum (negative fee)")]
    NegativeFee,
    #[error("script verification failed")]
    ScriptFailure,
    #[error("block has no transactions")]
    NoTransactions,
    #[error("first transaction in block must be coinbase")]
    InvalidCoinbase,
    #[error("block header merkle root mismatch: expected {expected}, computed {actual}")]
    InvalidMerkleRoot {
        expected: bitcrab_common::types::hash::Hash256,
        actual: bitcrab_common::types::hash::Hash256,
    },
}

/// The main validator for consensus rules.
pub struct TransactionValidator;

impl TransactionValidator {
    /// Perform stateless "CheckTransaction" rules.
    ///
    /// These checks don't need the UTXO set or blockchain context.
    pub fn check_transaction(tx: &Transaction) -> Result<(), ValidationError> {
        // 1. Basic size checks (handled during decoding, but we can double check limits)

        // 2. Ensure inputs and outputs are not empty
        if tx.inputs.is_empty() {
            return Err(ValidationError::NoInputs);
        }
        if tx.outputs.is_empty() {
            return Err(ValidationError::NoOutputs);
        }

        // 3. Check for overflow and range of outputs
        let mut total_output_value = Amount::ZERO;
        for output in &tx.outputs {
            if !output.value.is_valid() {
                return Err(ValidationError::AmountOutOfRange);
            }
            total_output_value = total_output_value
                .checked_add(output.value)
                .ok_or(ValidationError::TotalAmountOutOfRange)?;
        }

        if !total_output_value.is_valid() {
            return Err(ValidationError::TotalAmountOutOfRange);
        }

        // 4. Check for duplicate inputs (optional here, but good for early rejection)

        Ok(())
    }

    /// Perform context-aware validation against a UTXO view.
    ///
    /// Returns (fee, spent_coins) on success.
    pub fn contextual_check_transaction<V: CoinsView>(
        tx: &Transaction,
        view: &V,
        _height: bitcrab_common::types::block::BlockHeight,
    ) -> Result<(Amount, Vec<bitcrab_common::types::coin::Coin>), ValidationError> {
        // 1. Coinbase transactions skip this (they are handled during block connect)
        if tx.is_coinbase() {
            return Ok((Amount::ZERO, Vec::new()));
        }

        let mut total_input_value = Amount::ZERO;
        let mut spent_coins = Vec::with_capacity(tx.inputs.len());

        // 2. Ensure all inputs exist in the UTXO set and sum their values
        for input in &tx.inputs {
            let coin = view.get_coin(&input.previous_output).ok_or_else(|| {
                ValidationError::InputMissingOrSpent(input.previous_output.clone())
            })?;

            total_input_value = total_input_value
                .checked_add(coin.output.value)
                .ok_or(ValidationError::TotalAmountOutOfRange)?;

            spent_coins.push(coin.clone());
        }

        // 3. Calculate total output value
        let mut total_output_value = Amount::ZERO;
        for output in &tx.outputs {
            total_output_value = total_output_value
                .checked_add(output.value)
                .ok_or(ValidationError::TotalAmountOutOfRange)?;
        }

        // 4. Ensure no negative fee
        if total_input_value < total_output_value {
            return Err(ValidationError::NegativeFee);
        }

        // 5. Calculate fee
        let fee = total_input_value
            .checked_sub(total_output_value)
            .ok_or(ValidationError::NegativeFee)?;

        // 6. Signature / Script Verification (PHASE 5)
        for (i, input) in tx.inputs.iter().enumerate() {
            let coin = &spent_coins[i];

            // Generate Sighash (SIGHASH_ALL = 1)
            let sighash = tx.signature_hash(i, &coin.output.script_pubkey, 1);

            // Execute Script
            ScriptInterpreter::verify_script(
                &input.script_sig,
                &coin.output.script_pubkey,
                &input.witness,
                sighash,
            )
            .map_err(|_| ValidationError::ScriptFailure)?;
        }

        Ok((fee, spent_coins))
    }

    /// Verify a complete block's consensus rules and connect it to the view.
    pub fn connect_block<V: CoinsView>(
        block: &bitcrab_common::types::block::Block,
        height: bitcrab_common::types::block::BlockHeight,
        view: &mut CoinsViewCache<V>,
    ) -> Result<(Amount, BlockUndo), ValidationError> {
        // 1. Basic block structure checks
        if block.transactions.is_empty() {
            return Err(ValidationError::NoTransactions);
        }

        // 2. Check block header and merkle root
        let computed_root = block.compute_merkle_root();
        if block.header.merkle_root != computed_root {
            return Err(ValidationError::InvalidMerkleRoot {
                expected: block.header.merkle_root,
                actual: computed_root,
            });
        }

        // 3. First transaction must be coinbase
        if !block.transactions[0].is_coinbase() {
            return Err(ValidationError::InvalidCoinbase);
        }

        // 4. Stateless checks for all transactions
        for tx in &block.transactions {
            Self::check_transaction(tx)?;
        }

        let mut total_fees = Amount::ZERO;
        let mut block_undo = BlockUndo::new();

        // 4. Contextual validation and input consumption
        // (Skipping coinbase which is handled separately)
        for tx in block.transactions.iter().skip(1) {
            let (fee, spent_coins) = Self::contextual_check_transaction(tx, view, height)?;
            total_fees = total_fees
                .checked_add(fee)
                .ok_or(ValidationError::TotalAmountOutOfRange)?;

            // Record undo data
            for coin in spent_coins {
                block_undo.push(coin);
            }

            // Consume inputs
            for input in &tx.inputs {
                view.spend_coin(&input.previous_output);
            }

            // Add new outputs (not coinbase outputs yet)
            let txid = tx.txid();
            for (vout, output) in tx.outputs.iter().enumerate() {
                let coin = bitcrab_common::types::coin::Coin::new(output.clone(), height, false);
                view.add_coin(
                    bitcrab_common::types::transaction::OutPoint {
                        txid,
                        vout: vout as u32,
                    },
                    coin,
                    false,
                );
            }
        }

        // 5. Handle coinbase outputs
        let coinbase_tx = &block.transactions[0];
        let txid = coinbase_tx.txid();
        for (vout, output) in coinbase_tx.outputs.iter().enumerate() {
            let coin = bitcrab_common::types::coin::Coin::new(output.clone(), height, true);
            view.add_coin(
                bitcrab_common::types::transaction::OutPoint {
                    txid,
                    vout: vout as u32,
                },
                coin,
                false,
            );
        }

        // 6. Set the best block in the view
        view.set_best_block(block.header.block_hash());

        Ok((total_fees, block_undo))
    }
}
