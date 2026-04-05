use crate::api::{
    PrefixResult, StorageBackend, StorageLockedView, StorageReadView, StorageWriteBatch,
};
use crate::error::StoreError;
use rustc_hash::FxHashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};

type Table    = FxHashMap<Vec<u8>, Vec<u8>>;
type Database = FxHashMap<&'static str, Table>;

/// In-memory storage backend intended for testing and CI.
///
/// Uses an RCU (Read-Copy-Update) pattern:
/// - Readers clone the inner `Arc<Database>` and proceed without holding any lock.
/// - Writers acquire the outer `RwLock`, then use `Arc::make_mut` for copy-on-write
///   semantics. If active read snapshots exist, `make_mut` clones the full database.
#[derive(Debug)]
pub struct InMemoryBackend {
    inner: Arc<RwLock<Arc<Database>>>,
}

impl InMemoryBackend {
    pub fn open() -> Result<Self, StoreError> {
        Ok(Self {
            inner: Arc::new(RwLock::new(Arc::new(Database::default()))),
        })
    }
}

impl StorageBackend for InMemoryBackend {
    fn clear_table(&self, table: &'static str) -> Result<(), StoreError> {
        let mut guard = self.inner.write().map_err(|_| StoreError::LockPoisoned)?;
        let db = Arc::make_mut(&mut *guard);
        if let Some(t) = db.get_mut(table) {
            t.clear();
        }
        Ok(())
    }

    fn begin_read(&self) -> Result<Arc<dyn StorageReadView>, StoreError> {
        let snapshot = self.inner.read().map_err(|_| StoreError::LockPoisoned)?.clone();
        Ok(Arc::new(InMemoryReadTx { snapshot }))
    }

    fn begin_write(&self) -> Result<Box<dyn StorageWriteBatch + 'static>, StoreError> {
        Ok(Box::new(InMemoryWriteTx {
            backend: self.inner.clone(),
        }))
    }

    fn begin_locked(
        &self,
        table_name: &'static str,
    ) -> Result<Box<dyn StorageLockedView>, StoreError> {
        let snapshot = self.inner.read().map_err(|_| StoreError::LockPoisoned)?.clone();
        Ok(Box::new(InMemoryLocked { snapshot, table_name }))
    }

    fn create_checkpoint(&self, _path: &Path) -> Result<(), StoreError> {
        // Checkpoints are not supported for the in-memory backend.
        // Silently ignoring this call is safe — callers must not rely on
        // checkpoint files existing when using this backend.
        Ok(())
    }
}


pub struct InMemoryLocked {
    snapshot:   Arc<Database>,
    table_name: &'static str,
}

impl StorageLockedView for InMemoryLocked {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .snapshot
            .get(self.table_name)
            .and_then(|t| t.get(key))
            .cloned())
    }
}


pub struct InMemoryReadTx {
    snapshot: Arc<Database>,
}

/// An owned iterator over prefix-matched key-value pairs.
///
/// Wrapping `vec::IntoIter` in a named struct makes the `'_` lifetime bound
/// on `prefix_iterator` explicit: the iterator owns its data and does not
/// borrow from `InMemoryReadTx`, so it can outlive the read view safely.
pub struct InMemoryPrefixIter {
    results: std::vec::IntoIter<PrefixResult>,
}

impl Iterator for InMemoryPrefixIter {
    type Item = PrefixResult;

    fn next(&mut self) -> Option<Self::Item> {
        self.results.next()
    }
}

impl StorageReadView for InMemoryReadTx {
    fn get(&self, table: &'static str, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .snapshot
            .get(table)
            .and_then(|t| t.get(key))
            .cloned())
    }

    fn prefix_iterator(
        &self,
        table: &'static str,
        prefix: &[u8],
    ) -> Result<Box<dyn Iterator<Item = PrefixResult> + '_>, StoreError> {
        let prefix_vec = prefix.to_vec();

        let mut entries: Vec<(Vec<u8>, Vec<u8>)> = self
            .snapshot
            .get(table)
            .into_iter()
            .flat_map(|t| t.iter())
            .filter(|(k, _)| k.starts_with(&prefix_vec))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        // Sort to match RocksDB's lexicographic iteration order.
        entries.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));

        let results: Vec<PrefixResult> = entries
            .into_iter()
            .map(|(k, v)| Ok((k.into_boxed_slice(), v.into_boxed_slice())))
            .collect();

        Ok(Box::new(InMemoryPrefixIter {
            results: results.into_iter(),
        }))
    }
}


pub struct InMemoryWriteTx {
    backend: Arc<RwLock<Arc<Database>>>,
}

impl StorageWriteBatch for InMemoryWriteTx {
    fn put_batch(
        &mut self,
        table: &'static str,
        batch: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<(), StoreError> {
        let mut guard = self.backend.write().map_err(|_| StoreError::LockPoisoned)?;
        let db = Arc::make_mut(&mut *guard);
        let t = db.entry(table).or_default();
        for (key, value) in batch {
            t.insert(key, value);
        }
        Ok(())
    }

    fn delete(&mut self, table: &'static str, key: &[u8]) -> Result<(), StoreError> {
        let mut guard = self.backend.write().map_err(|_| StoreError::LockPoisoned)?;
        let db = Arc::make_mut(&mut *guard);
        if let Some(t) = db.get_mut(table) {
            t.remove(key);
        }
        Ok(())
    }

    fn commit(&mut self) -> Result<(), StoreError> {
        // Each put_batch and delete acquires its own write lock and applies
        // changes immediately, so there is nothing left to flush here.
        Ok(())
    }
}
