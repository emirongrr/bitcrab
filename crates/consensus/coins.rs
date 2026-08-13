//! UTXO Cache (CoinsView).
//!
//! Matches Bitcoin Core's `CCoinsView` and `CCoinsViewCache` in `src/coins.h`.
//! This provides a high-performance in-memory cache of unspent transaction outputs.

use bitcrab_common::types::coin::Coin;
use bitcrab_common::types::hash::BlockHash;
use bitcrab_common::types::transaction::OutPoint;
use bitcrab_storage::{block_manager::CoinUpdate, Store, StoreError};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

const ESTIMATED_CACHE_ENTRY_BYTES: usize = 256;

/// A trait for viewing the UTXO set.
pub trait CoinsView {
    /// Retrieve a coin from the view.
    fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin>;

    /// Get the best block hash according to this view.
    fn get_best_block(&self) -> Option<BlockHash>;
}

/// Metadata for a coin in the cache.
#[derive(Debug, Clone)]
pub struct CoinCacheEntry {
    pub coin: Option<Coin>, // None means the coin was spent
    pub is_dirty: bool,     // Modified in this cache, needs flushing
    pub is_fresh: bool,     // Didn't exist in base, so delete instead of update if spent
}

/// A cache that buffers UTXO changes before flushing them to a base view.
pub struct CoinsViewCache<V: CoinsView> {
    base: V,
    cache: HashMap<OutPoint, CoinCacheEntry>,
    best_block: Option<BlockHash>,
    /// Track blocks connected in this cache session for atomic height indexing.
    connected_blocks: Vec<(u32, BlockHash)>,
    max_entries: usize,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl<V: CoinsView> CoinsViewCache<V> {
    pub fn new(base: V, budget_bytes: usize) -> Self {
        let best_block = base.get_best_block();
        Self {
            base,
            cache: HashMap::new(),
            best_block,
            connected_blocks: Vec::new(),
            max_entries: (budget_bytes / ESTIMATED_CACHE_ENTRY_BYTES).max(1),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    pub fn set_best_block(&mut self, hash: BlockHash, height: u32) {
        self.best_block = Some(hash);
        self.connected_blocks.push((height, hash));
    }

    /// Add a new coin to the cache.
    pub fn add_coin(&mut self, outpoint: OutPoint, coin: Coin, possible_overwrite: bool) {
        let mut entry = CoinCacheEntry {
            coin: Some(coin),
            is_dirty: true,
            is_fresh: true,
        };

        if let Some(existing) = self.cache.get(&outpoint) {
            entry.is_fresh = existing.is_fresh;
        } else if !possible_overwrite {
            // If we know for sure it's not and wasn't in the cache/base, it's fresh.
        } else {
            // Check logically if it could be in base.
            // In Phase 2 we assume caller knows if it's fresh.
        }

        self.cache.insert(outpoint, entry);
    }

    /// Spend a coin, marking it as None in the cache.
    pub fn spend_coin(&mut self, outpoint: &OutPoint) -> Option<Coin> {
        let entry = self.cache.get(outpoint);

        if let Some(entry) = entry {
            entry.coin.as_ref()?;
            let coin = entry.coin.clone();

            if entry.is_fresh {
                self.cache.remove(outpoint);
            } else {
                self.cache.insert(
                    outpoint.clone(),
                    CoinCacheEntry {
                        coin: None,
                        is_dirty: true,
                        is_fresh: false,
                    },
                );
            }
            return coin;
        }

        // Not in cache, fetch from base then mark as spent (dirty)
        if let Some(coin) = self.base.get_coin(outpoint) {
            self.cache.insert(
                outpoint.clone(),
                CoinCacheEntry {
                    coin: None,
                    is_dirty: true,
                    is_fresh: false,
                },
            );
            return Some(coin);
        }

        None
    }

    /// Mark a coin spent after the caller already proved it exists.
    ///
    /// `ConnectBlock` reads every input while building undo data. Re-reading
    /// the same coin from RocksDB during the commit phase doubles random I/O.
    pub fn spend_coin_known(&mut self, outpoint: &OutPoint) {
        if self.cache.contains_key(outpoint) {
            let _ = self.spend_coin(outpoint);
            return;
        }

        self.cache.insert(
            outpoint.clone(),
            CoinCacheEntry {
                coin: None,
                is_dirty: true,
                is_fresh: false,
            },
        );
    }

    /// Convert cache entries into storage updates.
    pub fn to_updates(&self) -> HashMap<OutPoint, CoinUpdate> {
        let mut updates = HashMap::new();
        for (outpoint, entry) in &self.cache {
            if entry.is_dirty {
                match &entry.coin {
                    Some(coin) => {
                        updates.insert(outpoint.clone(), CoinUpdate::Add(coin.clone()));
                    }
                    None => {
                        if !entry.is_fresh {
                            updates.insert(outpoint.clone(), CoinUpdate::Remove);
                        }
                    }
                }
            }
        }
        updates
    }

    /// Clear flushed state after a successful write to the backing store.
    ///
    /// Bitcoin Core: `CCoinsViewCache::BatchWrite` — after writing dirty entries
    /// to the parent, the child cache discards all dirty entries so subsequent
    /// reads fall through to the (now-updated) base store.
    /// Without this, stale `None` (spent-marker) entries linger and cause
    /// false "input already spent" errors on the next `get_coin` call.
    pub fn clear_history(&mut self) {
        self.connected_blocks.clear();
        // Remove all dirty entries: they are now persisted in the base store.
        // Clean (unmodified) entries can stay — they are still valid cache hits.
        self.cache.retain(|_, entry| {
            if entry.is_dirty {
                if entry.coin.is_none() {
                    return false;
                }
                entry.is_dirty = false;
                entry.is_fresh = false;
            }
            true
        });
        self.trim_to_budget();
    }

    pub fn get_connected_blocks(&self) -> Vec<(u32, BlockHash)> {
        self.connected_blocks.clone()
    }

    /// Returns the current number of entries in the in-memory cache.
    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    pub fn cache_stats(&self) -> (u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
        )
    }

    fn trim_to_budget(&mut self) {
        let mut remaining = self.cache.len().saturating_sub(self.max_entries);
        self.cache.retain(|_, entry| {
            if remaining > 0 && !entry.is_dirty {
                remaining -= 1;
                false
            } else {
                true
            }
        });
    }
}

impl<V: CoinsView> CoinsView for CoinsViewCache<V> {
    fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        if let Some(entry) = self.cache.get(outpoint) {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return entry.coin.clone();
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        self.base.get_coin(outpoint)
    }

    fn get_best_block(&self) -> Option<BlockHash> {
        self.best_block.or_else(|| self.base.get_best_block())
    }
}

/// A wrapper around Store to implement CoinsView for the persistence layer.
pub struct StoreCoinsView {
    store: Store,
}

impl StoreCoinsView {
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    /// Flash a cache back to the store.
    pub async fn flush<V: CoinsView>(
        &self,
        cache: &mut CoinsViewCache<V>,
    ) -> Result<(), StoreError> {
        self.store
            .update_utxos(
                cache.to_updates(),
                cache.get_best_block(),
                cache.get_connected_blocks(),
            )
            .await?;
        cache.clear_history();
        Ok(())
    }
}

impl CoinsView for StoreCoinsView {
    fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        self.store.get_coin(outpoint).ok().flatten()
    }

    fn get_best_block(&self) -> Option<BlockHash> {
        self.store.get_best_block().ok().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcrab_common::types::{amount::Amount, block::BlockHeight, script::ScriptBuf};

    struct EmptyView;

    impl CoinsView for EmptyView {
        fn get_coin(&self, _outpoint: &OutPoint) -> Option<Coin> {
            None
        }

        fn get_best_block(&self) -> Option<BlockHash> {
            None
        }
    }

    fn outpoint(n: u32) -> OutPoint {
        OutPoint {
            txid: bitcrab_common::types::hash::Txid::from_bytes([n as u8; 32]),
            vout: n,
        }
    }

    fn coin() -> Coin {
        Coin::new(
            bitcrab_common::types::transaction::TxOut {
                value: Amount::from_sat(1).unwrap(),
                script_pubkey: ScriptBuf::new(),
            },
            BlockHeight(1),
            false,
        )
    }

    #[test]
    fn flushed_unspent_coins_remain_as_clean_cache_hits() {
        let mut cache = CoinsViewCache::new(EmptyView, 1024);
        let key = outpoint(1);
        cache.add_coin(key.clone(), coin(), false);

        cache.clear_history();

        assert!(cache.get_coin(&key).is_some());
        assert_eq!(cache.cache_stats(), (1, 0));
    }

    #[test]
    fn clean_cache_entries_are_trimmed_to_budget() {
        let mut cache = CoinsViewCache::new(EmptyView, ESTIMATED_CACHE_ENTRY_BYTES * 2);
        for n in 0..4 {
            cache.add_coin(outpoint(n), coin(), false);
        }

        cache.clear_history();

        assert_eq!(cache.cache_len(), 2);
    }
}
