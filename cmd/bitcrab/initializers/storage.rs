//! Storage initialization logic for the bitcrab binary.

use std::path::{Path, PathBuf};
use bitcrab_storage::{Store, EngineType, StoreError};
use bitcrab_net::p2p::message::Magic;
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

pub fn compute_effective_datadir(base: &Option<PathBuf>, magic: Magic) -> PathBuf {
    let base_path = base.clone().unwrap_or_else(|| {
        let mut path = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
        path.push("bitcrab");
        path
    });

    let suffix = match magic {
        Magic::Mainnet => "mainnet",
        Magic::Signet => "signet",
        Magic::Regtest => "regtest",
        _ => "unknown",
    };

    base_path.join(suffix)
}
