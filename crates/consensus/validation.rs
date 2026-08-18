//! Consensus Validation Engine.
//!
//! Implements the rules for validating Bitcoin transactions and blocks.
//! Matches Bitcoin Core's `src/consensus/tx_verify.cpp` and `src/validation.cpp`.

use bitcrab_common::constants::{
    COINBASE_MATURITY, INITIAL_BLOCK_REWARD, MAX_BLOCK_WEIGHT, MAX_COINBASE_SCRIPT_SIZE,
    MIN_COINBASE_SCRIPT_SIZE,
};
use bitcrab_common::types::amount::Amount;
use bitcrab_common::types::coin::Coin;
use bitcrab_common::types::transaction::OutPoint;
use bitcrab_common::types::transaction::Transaction;
use std::collections::HashMap;
use thiserror::Error;

use crate::coins::{CoinsView, CoinsViewCache};
use crate::engine::ConsensusEngine;
use crate::pow::{get_next_work_required, BlockIndexProvider};
use bitcrab_common::types::block::{Block, BlockHeight, BlockIndex};
use bitcrab_common::types::undo::BlockUndo;
use bitcrab_common::ChainParams;
use tokio::task::JoinSet;

/// The main validator for consensus rules.
pub struct TransactionValidator;

struct OverlayCoinsView<'a, V: CoinsView> {
    base: &'a V,
    coins: &'a HashMap<OutPoint, Option<Coin>>,
}

impl<V: CoinsView> CoinsView for OverlayCoinsView<'_, V> {
    fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        match self.coins.get(outpoint) {
            Some(coin) => coin.clone(),
            None => self.base.get_coin(outpoint),
        }
    }

    fn get_best_block(&self) -> Option<bitcrab_common::types::hash::BlockHash> {
        self.base.get_best_block()
    }
}

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

        // 4. Reject duplicate inputs.
        //
        // Bitcoin Core: the `vInOutPoints` set in `CheckTransaction`. Spending
        // the same outpoint twice inside one transaction would otherwise let a
        // coin be counted twice on the input side.
        let mut seen = std::collections::HashSet::with_capacity(tx.inputs.len());
        for input in &tx.inputs {
            if !seen.insert(&input.previous_output) {
                return Err(ValidationError::DuplicateInput);
            }
        }

        // 5. Coinbase scriptSig length, or prevout null-ness for everything else.
        if tx.is_coinbase() {
            let len = tx.inputs[0].script_sig.len();
            if !(MIN_COINBASE_SCRIPT_SIZE..=MAX_COINBASE_SCRIPT_SIZE).contains(&len) {
                return Err(ValidationError::BadCoinbaseScriptLength(len));
            }
        } else {
            for input in &tx.inputs {
                if input.previous_output.txid == bitcrab_common::types::hash::Txid::ZERO
                    && input.previous_output.vout == u32::MAX
                {
                    return Err(ValidationError::NullPrevout);
                }
            }
        }

        Ok(())
    }

    /// Block reward at `height`, excluding fees.
    ///
    /// Bitcoin Core: `GetBlockSubsidy()` in `src/validation.cpp`.
    pub fn block_subsidy(height: BlockHeight, params: &ChainParams) -> Amount {
        let halvings = height.0 / params.consensus.n_subsidy_halving_interval;
        // Shifting by 64 or more is undefined; Core forces the reward to zero.
        if halvings >= 64 {
            return Amount::ZERO;
        }
        Amount::from_sat(INITIAL_BLOCK_REWARD >> halvings).unwrap_or(Amount::ZERO)
    }

    /// Verify the coinbase encodes its own height.
    ///
    /// Bitcoin Core: the BIP 34 branch of `ContextualCheckBlock`. Without it two
    /// blocks could share a coinbase transaction, and therefore a txid — the
    /// duplicate-coinbase problem BIP 30 patched and BIP 34 made structural.
    fn check_bip34_height(block: &Block, height: BlockHeight) -> Result<(), ValidationError> {
        let expected = bitcrab_script::ScriptNum(height.0 as i64).encode();
        let mut expected_push = Vec::with_capacity(expected.len() + 1);
        bitcrab_script::script_ops::push_data(&mut expected_push, &expected);

        let script_sig = block.transactions[0].inputs[0].script_sig.as_bytes();
        if !script_sig.starts_with(&expected_push) {
            return Err(ValidationError::BadCoinbaseHeight { expected: height.0 });
        }
        Ok(())
    }

    /// Verify the BIP 141 witness commitment.
    ///
    /// Bitcoin Core: the segwit branch of `ContextualCheckBlock`.
    ///
    /// The commitment is `hash256(witness_merkle_root || witness_reserved)`,
    /// stored in the last coinbase output matching `6a24aa21a9ed`. It is
    /// optional — but when it is absent, no transaction may carry witness data,
    /// or that data would ride along uncommitted.
    fn check_witness_commitment(block: &Block) -> Result<(), ValidationError> {
        let coinbase = &block.transactions[0];

        let Some(commitment_index) = crate::signet::get_witness_commitment_index(coinbase) else {
            // No commitment: witness data anywhere in the block is unanchored.
            if block.transactions.iter().any(|tx| tx.is_segwit()) {
                return Err(ValidationError::UnexpectedWitness);
            }
            return Ok(());
        };

        // The nonce is the coinbase's single witness item, exactly 32 bytes.
        let witness = &coinbase.inputs[0].witness;
        if witness.len() != 1 || witness[0].len() != 32 {
            return Err(ValidationError::BadWitnessNonceSize);
        }

        // Witness merkle tree: the coinbase's wtxid is defined as zero, because
        // the commitment it would otherwise contain is inside that same tree.
        let mut leaves = Vec::with_capacity(block.transactions.len());
        leaves.push(bitcrab_common::types::hash::Hash256::ZERO);
        for tx in block.transactions.iter().skip(1) {
            leaves.push(bitcrab_common::types::hash::Hash256::from_bytes(
                *tx.wtxid().as_bytes(),
            ));
        }
        let witness_root = crate::signet::merkle_root(leaves);

        let mut preimage = Vec::with_capacity(64);
        preimage.extend_from_slice(witness_root.as_bytes());
        preimage.extend_from_slice(&witness[0]);
        let expected = bitcrab_common::types::hash::hash256(&preimage);

        let script = coinbase.outputs[commitment_index].script_pubkey.as_bytes();
        if script[6..38] != expected {
            return Err(ValidationError::WitnessCommitmentMismatch);
        }

        Ok(())
    }

    /// Perform context-aware validation against a UTXO view. (WITHOUT Script verification)
    pub fn contextual_check_transaction_metadata<V: CoinsView>(
        tx: &Transaction,
        view: &V,
        height: BlockHeight,
        _params: &ChainParams,
    ) -> Result<(Amount, Vec<bitcrab_common::types::coin::Coin>), ValidationError> {
        // 1. Coinbase transactions skip this
        if tx.is_coinbase() {
            return Ok((Amount::ZERO, Vec::new()));
        }

        let mut total_input_value = Amount::ZERO;
        let mut spent_coins = Vec::with_capacity(tx.inputs.len());

        // 2. Ensure all inputs exist and sum values
        for input in &tx.inputs {
            let coin = view.get_coin(&input.previous_output).ok_or_else(|| {
                ValidationError::InputMissingOrSpent(input.previous_output.clone())
            })?;

            // Bitcoin Core: `bad-txns-premature-spend-of-coinbase`. A coinbase
            // is only spendable 100 blocks later, so a reorg cannot invalidate
            // transactions that already spent a reward that no longer exists.
            if coin.is_coinbase && height.0.saturating_sub(coin.height.0) < COINBASE_MATURITY {
                return Err(ValidationError::PrematureCoinbaseSpend {
                    created: coin.height.0,
                    spent: height.0,
                });
            }

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

        Ok((fee, spent_coins))
    }

    /// Verify a block header against PoW and difficulty rules.
    pub fn check_block_header<P: BlockIndexProvider>(
        header: &bitcrab_common::types::block::BlockHeader,
        index_prev: &BlockIndex,
        params: &bitcrab_common::ChainParams,
        provider: &P,
    ) -> Result<(), ValidationError> {
        // 1. Check proof of work matches target
        if !header.meets_target() {
            return Err(ValidationError::InvalidProofOfWork);
        }

        // 2. Check difficulty retargeting matches Bitcoin Core GetNextWorkRequired
        let expected_bits = get_next_work_required(index_prev, header, &params.consensus, provider);
        if header.bits != expected_bits {
            return Err(ValidationError::WrongDifficulty {
                height: index_prev.height.0 + 1,
                expected: expected_bits,
                actual: header.bits,
            });
        }

        Ok(())
    }

    /// Perform stateless "CheckBlock" rules.
    ///
    /// Bitcoin Core: `CheckBlock` in `src/validation.cpp`.
    /// Does not require UTXO set or context.
    pub fn check_block(block: &Block, params: &ChainParams) -> Result<(), ValidationError> {
        // 1. Basic block structure checks
        if block.transactions.is_empty() {
            return Err(ValidationError::NoTransactions);
        }

        // 2. Check merkle root
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

        // 5. Block weight.
        //
        // Bitcoin Core: `CheckBlock` — weight is base size counted four times
        // plus the witness bytes, so a block full of witness data still fits
        // where an equivalent pre-segwit block would not.
        let weight = block.weight();
        if weight > MAX_BLOCK_WEIGHT {
            return Err(ValidationError::BlockWeightTooLarge(weight));
        }

        // 6. BIP 325 signet block solution.
        //
        // Bitcoin Core checks this inside CheckBlock, before any chainstate is
        // touched, so an unsigned block can never reach the UTXO set. Gate on
        // `signet_blocks` rather than the message-start bytes: a custom signet
        // has its own magic but the same requirement.
        if params.consensus.signet_blocks {
            crate::signet::check_signet_block_solution(block, params)
                .map_err(ValidationError::SignetSolution)?;
        }

        Ok(())
    }

    /// Perform context-aware block connection.
    ///
    /// Bitcoin Core: `ConnectBlock` in `src/validation.cpp`.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_block<V: CoinsView, P: BlockIndexProvider>(
        block: &Block,
        height: BlockHeight,
        index_prev: &BlockIndex,
        view: &mut CoinsViewCache<V>,
        params: &ChainParams,
        provider: &P,
        check_scripts: bool,
        engine: ConsensusEngine,
    ) -> Result<(Amount, BlockUndo), ValidationError> {
        // 0. Stateless Checks
        Self::check_block(block, params)?;

        // 1. Header Validation (Difficulty/PoW) - Contextual
        Self::check_block_header(&block.header, index_prev, params, provider)?;

        // 2. Contextual block rules that need the height.
        if height.0 >= params.consensus.bip34_height {
            Self::check_bip34_height(block, height)?;
        }
        if height.0 >= params.consensus.segwit_height {
            Self::check_witness_commitment(block)?;
        }

        let mut total_fees = Amount::ZERO;
        let mut block_undo = BlockUndo::new();

        let mut verification_set = JoinSet::new();
        let mut overlay = HashMap::<OutPoint, Option<Coin>>::new();
        let mut validated_spends = Vec::with_capacity(block.transactions.len().saturating_sub(1));

        // Validate against an isolated overlay. Bitcoin Core's ConnectBlock
        // must not leave CCoinsViewCache mutated when script checks fail.
        for tx in block.transactions.iter().skip(1) {
            let overlay_view = OverlayCoinsView {
                base: view,
                coins: &overlay,
            };
            let (fee, spent_coins) =
                Self::contextual_check_transaction_metadata(tx, &overlay_view, height, params)?;
            total_fees = total_fees
                .checked_add(fee)
                .ok_or(ValidationError::TotalAmountOutOfRange)?;

            // Prepare parallel script verification tasks
            let tx_clone = tx.clone();
            let spent_coins_clone = spent_coins.clone();
            if check_scripts {
                verification_set.spawn_blocking(move || {
                    engine.verify_transaction(&tx_clone, &spent_coins_clone)
                });
            }

            // Record undo data
            for coin in spent_coins {
                block_undo.push(coin);
            }

            let mut tx_spends = Vec::with_capacity(tx.inputs.len());
            for input in &tx.inputs {
                overlay.insert(input.previous_output.clone(), None);
                tx_spends.push(input.previous_output.clone());
            }
            validated_spends.push(tx_spends);

            let txid = tx.txid();
            for (vout, output) in tx.outputs.iter().enumerate() {
                let coin = Coin::new(output.clone(), height, false);
                overlay.insert(
                    OutPoint {
                        txid,
                        vout: vout as u32,
                    },
                    Some(coin),
                );
            }
        }

        // Await all parallel script verifications
        while let Some(res) = verification_set.join_next().await {
            res.map_err(|_| ValidationError::ScriptFailure)??;
        }

        // Commit the successfully verified block's changes to the real view.
        for (tx, tx_spends) in block.transactions.iter().skip(1).zip(validated_spends) {
            for outpoint in tx_spends {
                view.spend_coin_known(&outpoint);
            }

            let txid = tx.txid();
            for (vout, output) in tx.outputs.iter().enumerate() {
                view.add_coin(
                    OutPoint {
                        txid,
                        vout: vout as u32,
                    },
                    Coin::new(output.clone(), height, false),
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

        // 6. The coinbase may claim the subsidy plus the fees, and no more.
        //
        // Bitcoin Core: `bad-cb-amount` in `ConnectBlock`. This is the rule that
        // stops a miner minting coins out of nothing; without it every other
        // check here is decoration.
        let mut coinbase_value = Amount::ZERO;
        for output in &coinbase_tx.outputs {
            coinbase_value = coinbase_value
                .checked_add(output.value)
                .ok_or(ValidationError::TotalAmountOutOfRange)?;
        }

        let allowed = Self::block_subsidy(height, params)
            .checked_add(total_fees)
            .ok_or(ValidationError::TotalAmountOutOfRange)?;

        if coinbase_value > allowed {
            return Err(ValidationError::CoinbaseValueTooHigh {
                claimed: coinbase_value.to_sat(),
                allowed: allowed.to_sat(),
            });
        }

        // 7. Set the best block in the view
        view.set_best_block(block.header.block_hash(), height.0);

        Ok((total_fees, block_undo))
    }
}

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
    #[error("script verification failed for input {index}: {error}")]
    ScriptError {
        index: usize,
        error: bitcrab_script::ScriptError,
    },
    #[error("requested consensus reference engine is not compiled")]
    ReferenceEngineUnavailable,
    #[error("block has no transactions")]
    NoTransactions,
    #[error("first transaction in block must be coinbase")]
    InvalidCoinbase,
    #[error("block header merkle root mismatch: expected {expected}, computed {actual}")]
    InvalidMerkleRoot {
        expected: bitcrab_common::types::hash::Hash256,
        actual: bitcrab_common::types::hash::Hash256,
    },
    #[error("invalid proof of work")]
    InvalidProofOfWork,
    #[error(
        "wrong difficulty at height {height}: expected {expected:#010x}, actual {actual:#010x}"
    )]
    WrongDifficulty {
        height: u32,
        expected: u32,
        actual: u32,
    },
    #[error("signet block solution invalid: {0}")]
    SignetSolution(#[from] crate::signet::SignetError),
    #[error("transaction spends the same outpoint twice")]
    DuplicateInput,
    #[error("coinbase scriptSig length {0} outside the permitted 2..=100")]
    BadCoinbaseScriptLength(usize),
    #[error("non-coinbase transaction has a null prevout")]
    NullPrevout,
    #[error("coinbase does not encode its height (expected {expected})")]
    BadCoinbaseHeight { expected: u32 },
    #[error("coinbase witness nonce must be a single 32-byte item")]
    BadWitnessNonceSize,
    #[error("witness commitment does not match the witness merkle root")]
    WitnessCommitmentMismatch,
    #[error("block carries witness data but commits to none")]
    UnexpectedWitness,
    #[error("block weight {0} exceeds the maximum")]
    BlockWeightTooLarge(u64),
    #[error("coinbase claims {claimed} satoshis but only {allowed} are allowed")]
    CoinbaseValueTooHigh { claimed: u64, allowed: u64 },
    #[error("coinbase created at height {created} spent at {spent}, before maturity")]
    PrematureCoinbaseSpend { created: u32, spent: u32 },
}
