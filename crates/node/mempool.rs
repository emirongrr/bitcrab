use bitcrab_common::types::{hash::Txid, transaction::Transaction};
use std::collections::HashMap;
use std::sync::Mutex;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MempoolError {
    #[error("Transaction already in mempool")]
    Duplicate,
}

/// The Memory Pool for pending transactions.
///
/// Bitcoin Core: `CTxMemPool`
pub struct Mempool {
    txs: Mutex<HashMap<Txid, Transaction>>,
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

impl Mempool {
    pub fn new() -> Self {
        Self {
            txs: Mutex::new(HashMap::new()),
        }
    }

    /// Accepts a valid transaction into the mempool.
    ///
    /// Bitcoin Core: `AcceptToMemoryPool`
    pub fn accept_tx(&self, tx: Transaction) -> Result<(), MempoolError> {
        // Basic validation logic would go here:
        // 1. Is it a coinbase? (reject)
        // 2. Is it already in the pool? (check)
        // 3. Are inputs available / final?
        // 4. Do scripts pass?

        let mut txs = self.txs.lock().unwrap();
        let txid = tx.txid();
        if txs.contains_key(&txid) {
            return Err(MempoolError::Duplicate);
        }

        txs.insert(txid, tx);
        Ok(())
    }

    /// Remove a transaction by txid.
    pub fn remove(&self, txid: &Txid) {
        let mut txs = self.txs.lock().unwrap();
        txs.remove(txid);
    }

    /// Get all pending transactions (e.g., for block template building).
    pub fn get_all(&self) -> Vec<Transaction> {
        let txs = self.txs.lock().unwrap();
        txs.values().cloned().collect()
    }
}
