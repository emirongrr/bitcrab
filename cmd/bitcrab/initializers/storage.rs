//! Storage initialization logic for the bitcrab binary.

use bitcrab_common::types::magic::Magic;
use bitcrab_storage::{EngineType, Store, StoreError};
use std::path::{Path, PathBuf};
use tracing::info;

/// Opens a pre-existing Store or creates a new one.
pub async fn init_store(datadir: &Path, magic: Magic) -> Result<Store, StoreError> {
    info!("[init] initializing storage at {:?}", datadir);

    // Ensure parent directories exist
    if let Some(parent) = datadir.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    Store::new(datadir.to_path_buf(), EngineType::RocksDB, magic)
}

/// Opens an in-memory Store (for testing/dev).
pub fn init_memory_store(magic: Magic) -> Result<Store, StoreError> {
    Store::in_memory(magic)
}

pub fn compute_effective_datadir(
    base: &Option<PathBuf>,
    chain: bitcrab_common::ChainType,
) -> PathBuf {
    let base_path = base.clone().unwrap_or_else(|| {
        let mut path = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
        path.push("bitcrab");
        path
    });

    match chain.datadir_suffix() {
        Some(suffix) => base_path.join(suffix),
        None => base_path,
    }
}
