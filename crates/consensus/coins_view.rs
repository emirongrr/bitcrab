//! UTXO Cache (CoinsView).
//!
//! Matches Bitcoin Core's `CCoinsView` and `CCoinsViewCache` in `src/coins.h`.
//! This provides a high-performance in-memory cache of unspent transaction outputs.

use bitcrab_common::types::coin::Coin;
use bitcrab_common::types::hash::BlockHash;
use bitcrab_common::types::transaction::OutPoint;
use bitcrab_storage::{worker::CoinUpdate, Store, StoreError};
use std::collections::HashMap;

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
}

impl<V: CoinsView> CoinsViewCache<V> {
    pub fn new(base: V) -> Self {
        let best_block = base.get_best_block();
        Self {
            base,
            cache: HashMap::new(),
            best_block,
        }
    }

    pub fn set_best_block(&mut self, hash: BlockHash) {
        self.best_block = Some(hash);
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
            if entry.coin.is_none() {
                return None;
            }
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
}

impl<V: CoinsView> CoinsView for CoinsViewCache<V> {
    fn get_coin(&self, outpoint: &OutPoint) -> Option<Coin> {
        if let Some(entry) = self.cache.get(outpoint) {
            return entry.coin.clone();
        }
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
    pub async fn flush<V: CoinsView>(&self, cache: &CoinsViewCache<V>) -> Result<(), StoreError> {
        self.store
            .update_utxos(cache.to_updates(), cache.get_best_block())
            .await
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
