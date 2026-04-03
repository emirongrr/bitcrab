use crate::error::StoreError;
use std::path::Path;
use std::sync::Arc;

pub mod tables;

pub type PrefixResult = Result<(Box<[u8]>, Box<[u8]>), StoreError>;

/// Interface for key-value storage backends
pub trait StorageBackend: Send + Sync {
    fn clear_table(&self, table: &'static str) -> Result<(), StoreError>;
    fn begin_read(&self) -> Result<Arc<dyn StorageReadView>, StoreError>;
    fn begin_write(&self) -> Result<Box<dyn StorageWriteBatch + 'static>, StoreError>;
    fn begin_locked(
        &self,
        table_name: &'static str,
    ) -> Result<Box<dyn StorageLockedView>, StoreError>;
    fn create_checkpoint(&self, path: &Path) -> Result<(), StoreError>;
}

pub trait StorageReadView: Send + Sync {
    fn get(&self, table: &'static str, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError>;
    fn prefix_iterator(
        &self,
        table: &'static str,
        prefix: &[u8],
    ) -> Result<Box<dyn Iterator<Item = PrefixResult> + '_>, StoreError>;
}

pub trait StorageWriteBatch: Send + Sync {
    fn put(&mut self, table: &'static str, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        self.put_batch(table, vec![(key.to_vec(), value.to_vec())])
    }
    fn put_batch(
        &mut self,
        table: &'static str,
        batch: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<(), StoreError>;
    fn delete(&mut self, table: &'static str, key: &[u8]) -> Result<(), StoreError>;
    fn commit(&mut self) -> Result<(), StoreError>;
}

pub trait StorageLockedView: Send + Sync {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError>;
}
