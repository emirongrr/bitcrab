use crate::api::{
    PrefixResult, StorageBackend, StorageLockedView, StorageReadView, StorageWriteBatch,
    tables::{BLOCK_INDEX, CHAIN_META, TABLES, UTXOS},
};
use crate::error::StoreError;
use rocksdb::{
    BlockBasedOptions, Cache, ColumnFamilyDescriptor, DBWithThreadMode, MultiThreaded, Options,
    SnapshotWithThreadMode, WriteBatch, checkpoint::Checkpoint,
};
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use tracing::{info, warn};

/// RocksDB storage backend for production use.
///
/// Maps Bitcoin Core's two LevelDB databases (`blocks/index` and `chainstate`)
/// onto a single RocksDB instance with one column family per logical table.
/// Raw block data is not stored here — it lives in flat `blk*.dat` files
/// managed by the block file layer.
///
/// Write batches accumulate operations in memory and flush atomically on
/// [`commit`](StorageWriteBatch::commit), providing crash-safe writes via
/// the WAL.
#[derive(Debug)]
pub struct RocksDBBackend {
    db: Arc<DBWithThreadMode<MultiThreaded>>,
}

impl RocksDBBackend {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        opts.set_max_open_files(-1);
        opts.set_max_file_opening_threads(16);
        opts.set_max_background_jobs(8);

        opts.set_level_zero_file_num_compaction_trigger(2);
        opts.set_level_zero_slowdown_writes_trigger(10);
        opts.set_level_zero_stop_writes_trigger(16);
        opts.set_target_file_size_base(512 * 1024 * 1024); // 512MB
        opts.set_max_bytes_for_level_base(2 * 1024 * 1024 * 1024); // 2GB L1
        opts.set_max_bytes_for_level_multiplier(10.0);
        opts.set_level_compaction_dynamic_level_bytes(true);

        opts.set_db_write_buffer_size(1024 * 1024 * 1024); // 1GB
        opts.set_write_buffer_size(128 * 1024 * 1024); // 128MB
        opts.set_max_write_buffer_number(4);
        opts.set_min_write_buffer_number_to_merge(2);

        // Point-in-time recovery ensures the WAL is replayed consistently
        // after an unclean shutdown.
        opts.set_wal_recovery_mode(rocksdb::DBRecoveryMode::PointInTime);
        opts.set_max_total_wal_size(2 * 1024 * 1024 * 1024); // 2GB
        opts.set_wal_bytes_per_sync(32 * 1024 * 1024); // 32MB
        opts.set_bytes_per_sync(32 * 1024 * 1024); // 32MB
        opts.set_use_fsync(false); // fdatasync is sufficient

        opts.set_enable_pipelined_write(true);
        opts.set_allow_concurrent_memtable_write(true);
        opts.set_enable_write_thread_adaptive_yield(true);
        opts.set_compaction_readahead_size(4 * 1024 * 1024); // 4MB
        opts.set_advise_random_on_open(false);
        opts.set_compression_type(rocksdb::DBCompressionType::None);

        let existing_cfs =
            DBWithThreadMode::<MultiThreaded>::list_cf(&opts, path.as_ref())
                .unwrap_or_else(|_| vec!["default".to_string()]);

        let mut all_cfs_to_open = HashSet::new();
        all_cfs_to_open.extend(existing_cfs.iter().cloned());
        all_cfs_to_open.extend(TABLES.iter().map(|t| t.to_string()));

        // Shared LRU block cache across all column families to avoid
        // per-CF cache fragmentation under concurrent read workloads.
        let block_cache = Cache::new_lru_cache(4 * 1024 * 1024 * 1024); // 4GB

        let mut cf_descriptors = Vec::new();
        for cf_name in &all_cfs_to_open {
            let mut cf_opts = Options::default();

            cf_opts.set_level_zero_file_num_compaction_trigger(4);
            cf_opts.set_level_zero_slowdown_writes_trigger(20);
            cf_opts.set_level_zero_stop_writes_trigger(36);

            match cf_name.as_str() {
                // Block index: fixed-size keys (1 + 32 bytes), random reads
                // during validation and header sync. Bloom filter cuts
                // point-lookup I/O significantly. No compression — values
                // are already compact (serialized CBlockIndex, ~100 bytes).
                BLOCK_INDEX => {
                    cf_opts.set_compression_type(rocksdb::DBCompressionType::None);
                    cf_opts.set_write_buffer_size(64 * 1024 * 1024); // 64MB
                    cf_opts.set_max_write_buffer_number(3);
                    cf_opts.set_target_file_size_base(128 * 1024 * 1024); // 128MB

                    let mut block_opts = BlockBasedOptions::default();
                    block_opts.set_block_size(16 * 1024); // 16KB
                    block_opts.set_bloom_filter(10.0, false); // 10 bits per key
                    block_opts.set_block_cache(&block_cache);
                    cf_opts.set_block_based_table_factory(&block_opts);
                }

                // UTXO set: very high random read/write rate — every
                // transaction input requires a coin lookup and deletion.
                // Large write buffers reduce compaction pressure during IBD.
                // Bloom filter is critical: most lookups hit the memtable
                // or the filter before touching SST files.
                // No compression — coin records are small and already
                // entropy-dense (scripts, amounts).
                UTXOS => {
                    cf_opts.set_compression_type(rocksdb::DBCompressionType::None);
                    cf_opts.set_write_buffer_size(256 * 1024 * 1024); // 256MB
                    cf_opts.set_max_write_buffer_number(6);
                    cf_opts.set_min_write_buffer_number_to_merge(2);
                    cf_opts.set_target_file_size_base(256 * 1024 * 1024); // 256MB
                    cf_opts.set_memtable_prefix_bloom_ratio(0.1);

                    let mut block_opts = BlockBasedOptions::default();
                    block_opts.set_block_size(16 * 1024); // 16KB
                    block_opts.set_bloom_filter(10.0, false); // 10 bits per key
                    block_opts.set_block_cache(&block_cache);
                    cf_opts.set_block_based_table_factory(&block_opts);
                }

                // Chain metadata: tiny table, very low write rate.
                // Holds a handful of keys (best block hash, last file
                // number, feature flags). Default settings are sufficient.
                CHAIN_META => {
                    cf_opts.set_compression_type(rocksdb::DBCompressionType::None);
                    cf_opts.set_write_buffer_size(4 * 1024 * 1024); // 4MB
                    cf_opts.set_max_write_buffer_number(2);
                    cf_opts.set_target_file_size_base(8 * 1024 * 1024); // 8MB

                    let mut block_opts = BlockBasedOptions::default();
                    block_opts.set_block_size(4 * 1024); // 4KB
                    block_opts.set_block_cache(&block_cache);
                    cf_opts.set_block_based_table_factory(&block_opts);
                }

                // Unknown column families from older schema versions.
                // Conservative defaults — they will be dropped after open.
                _ => {
                    cf_opts.set_compression_type(rocksdb::DBCompressionType::None);
                    cf_opts.set_write_buffer_size(64 * 1024 * 1024); // 64MB
                    cf_opts.set_max_write_buffer_number(3);
                    cf_opts.set_target_file_size_base(128 * 1024 * 1024); // 128MB

                    let mut block_opts = BlockBasedOptions::default();
                    block_opts.set_block_size(16 * 1024);
                    block_opts.set_block_cache(&block_cache);
                    cf_opts.set_block_based_table_factory(&block_opts);
                }
            }

            cf_descriptors.push(ColumnFamilyDescriptor::new(cf_name, cf_opts));
        }

        let db = DBWithThreadMode::<MultiThreaded>::open_cf_descriptors(
            &opts,
            path.as_ref(),
            cf_descriptors,
        )
        .map_err(|e| StoreError::Custom(format!("failed to open RocksDB: {e}")))?;

        // Drop column families that were present on disk but are no longer
        // defined in TABLES. This keeps the on-disk layout in sync with the
        // current schema after migrations.
        for cf_name in &existing_cfs {
            if cf_name != "default" && !TABLES.contains(&cf_name.as_str()) {
                warn!("dropping obsolete column family: {cf_name}");
                let _ = db
                    .drop_cf(cf_name)
                    .inspect(|_| info!("dropped column family: {cf_name}"))
                    .inspect_err(|e| warn!("failed to drop column family '{cf_name}': {e}"));
            }
        }

        Ok(Self { db: Arc::new(db) })
    }
}

impl Drop for RocksDBBackend {
    fn drop(&mut self) {
        // Cancel background compaction and flush threads before the DB handle
        // is deallocated. Without this, RocksDB may access freed memory.
        // See: https://github.com/facebook/rocksdb/issues/11349
        if let Some(db) = Arc::get_mut(&mut self.db) {
            db.cancel_all_background_work(true);
        }
    }
}

// ── StorageBackend ────────────────────────────────────────────────────────────

impl StorageBackend for RocksDBBackend {
    fn clear_table(&self, table: &'static str) -> Result<(), StoreError> {
        let cf = self
            .db
            .cf_handle(table)
            .ok_or_else(|| StoreError::Custom(format!("column family not found: {table}")))?;

        let mut batch = WriteBatch::default();
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        for item in iter {
            let (key, _) = item.map_err(|e| StoreError::Custom(e.to_string()))?;
            batch.delete_cf(&cf, key);
        }

        self.db
            .write(batch)
            .map_err(|e| StoreError::Custom(format!("clear_table write failed: {e}")))
    }

    fn begin_read(&self) -> Result<Arc<dyn StorageReadView>, StoreError> {
        Ok(Arc::new(RocksDBReadTx { db: self.db.clone() }))
    }

    fn begin_write(&self) -> Result<Box<dyn StorageWriteBatch + 'static>, StoreError> {
        Ok(Box::new(RocksDBWriteTx {
            db:    self.db.clone(),
            batch: WriteBatch::default(),
        }))
    }

    fn begin_locked(
        &self,
        table_name: &'static str,
    ) -> Result<Box<dyn StorageLockedView>, StoreError> {
        // SAFETY: `db` is leaked so it outlives the snapshot and column family
        // handle, both of which hold a `'static` reference to it. The original
        // `Box` is reconstructed and dropped in `RocksDBLocked::drop`.
        let db: &'static Arc<DBWithThreadMode<MultiThreaded>> =
            Box::leak(Box::new(self.db.clone()));
        let lock = db.snapshot();
        let cf = db
            .cf_handle(table_name)
            .ok_or_else(|| StoreError::Custom(format!("column family not found: {table_name}")))?;

        Ok(Box::new(RocksDBLocked { db, lock, cf }))
    }

    fn create_checkpoint(&self, path: &Path) -> Result<(), StoreError> {
        let checkpoint = Checkpoint::new(&self.db)
            .map_err(|e| StoreError::Custom(format!("checkpoint init failed: {e}")))?;

        checkpoint
            .create_checkpoint(path)
            .map_err(|e| StoreError::Custom(format!("checkpoint write failed at {path:?}: {e}")))
    }
}

// ── Read view ─────────────────────────────────────────────────────────────────

/// A read-only view backed by the live RocksDB instance.
///
/// Reads are not snapshot-isolated — concurrent writes may be visible.
/// Use [`RocksDBLocked`] when snapshot isolation is required.
pub struct RocksDBReadTx {
    db: Arc<DBWithThreadMode<MultiThreaded>>,
}

impl StorageReadView for RocksDBReadTx {
    fn get(&self, table: &'static str, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        let cf = self
            .db
            .cf_handle(table)
            .ok_or_else(|| StoreError::Custom(format!("column family not found: {table}")))?;

        self.db
            .get_cf(&cf, key)
            .map_err(|e| StoreError::Custom(format!("get failed on {table}: {e}")))
    }

    fn prefix_iterator(
        &self,
        table: &'static str,
        prefix: &[u8],
    ) -> Result<Box<dyn Iterator<Item = PrefixResult> + '_>, StoreError> {
        let cf = self
            .db
            .cf_handle(table)
            .ok_or_else(|| StoreError::Custom(format!("column family not found: {table}")))?;

        let iter = self
            .db
            .prefix_iterator_cf(&cf, prefix)
            .map(|r| r.map_err(|e| StoreError::Custom(format!("iteration failed: {e}"))));

        Ok(Box::new(iter))
    }
}

// ── Write batch ───────────────────────────────────────────────────────────────

/// An atomic write batch backed by RocksDB's native `WriteBatch`.
///
/// Operations accumulate in memory and are written to disk as a single
/// atomic unit on [`commit`](StorageWriteBatch::commit). If the process
/// crashes before commit, no partial writes are visible on restart.
pub struct RocksDBWriteTx {
    db:    Arc<DBWithThreadMode<MultiThreaded>>,
    batch: WriteBatch,
}

// WriteBatch is not Send by default in some rocksdb crate versions.
unsafe impl Send for RocksDBWriteTx {}
unsafe impl Sync for RocksDBWriteTx {}

impl StorageWriteBatch for RocksDBWriteTx {
    fn put(&mut self, table: &'static str, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        let cf = self
            .db
            .cf_handle(table)
            .ok_or_else(|| StoreError::Custom(format!("column family not found: {table}")))?;
        self.batch.put_cf(&cf, key, value);
        Ok(())
    }

    fn put_batch(
        &mut self,
        table: &'static str,
        batch: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<(), StoreError> {
        let cf = self
            .db
            .cf_handle(table)
            .ok_or_else(|| StoreError::Custom(format!("column family not found: {table}")))?;

        for (key, value) in batch {
            self.batch.put_cf(&cf, key, value);
        }
        Ok(())
    }

    fn delete(&mut self, table: &'static str, key: &[u8]) -> Result<(), StoreError> {
        let cf = self
            .db
            .cf_handle(table)
            .ok_or_else(|| StoreError::Custom(format!("column family not found: {table}")))?;
        self.batch.delete_cf(&cf, key);
        Ok(())
    }

    fn commit(&mut self) -> Result<(), StoreError> {
        // `std::mem::take` replaces `self.batch` with an empty WriteBatch,
        // giving ownership to `db.write()` which consumes it.
        let batch = std::mem::take(&mut self.batch);
        self.db
            .write(batch)
            .map_err(|e| StoreError::Custom(format!("commit failed: {e}")))
    }
}

// ── Locked view ───────────────────────────────────────────────────────────────

/// A snapshot-isolated read view pinned to a single column family.
///
/// The snapshot is taken at construction time; subsequent writes are not
/// visible through this view. Primarily used during UTXO set iteration
/// where a consistent point-in-time view is required.
pub struct RocksDBLocked {
    db:   &'static Arc<DBWithThreadMode<MultiThreaded>>,
    lock: SnapshotWithThreadMode<'static, DBWithThreadMode<MultiThreaded>>,
    cf:   Arc<rocksdb::BoundColumnFamily<'static>>,
}

unsafe impl Send for RocksDBLocked {}
unsafe impl Sync for RocksDBLocked {}

impl StorageLockedView for RocksDBLocked {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        self.lock
            .get_cf(&self.cf, key)
            .map_err(|e| StoreError::Custom(format!("locked get failed: {e}")))
    }
}

impl Drop for RocksDBLocked {
    fn drop(&mut self) {
        // Reconstruct and drop the `Box` that was leaked in `begin_locked`.
        // This must run after `lock` and `cf` are dropped since both hold
        // references into `db`.
        unsafe {
            drop(Box::from_raw(
                self.db as *const Arc<DBWithThreadMode<MultiThreaded>>
                    as *mut Arc<DBWithThreadMode<MultiThreaded>>,
            ));
        }
    }
}