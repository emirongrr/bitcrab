//! Integration tests for storage layer.
//!
//! Tests combining multiple components: Handle, Worker, and BlockFiles.

use bitcrab_common::types::block::{BlockHeader, BlockHeight};
use bitcrab_common::types::hash::{BlockHash, Hash256};
use bitcrab_storage::{EngineType, Magic, Store};
use std::sync::atomic::{AtomicU64, Ordering};

fn test_dir() -> std::path::PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    std::env::current_dir()
        .expect("current directory")
        .join("target")
        .join(format!(
            "storage_integration_{}_{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
}

#[tokio::test]
async fn storage_integration_basic_flow() {
    let magic = Magic::REGTEST;
    // The KV backend is in-memory, while flat block files still require an
    // isolated directory just like Bitcoin Core's functional test datadirs.
    let dir = test_dir();
    let store = Store::new(&dir, EngineType::InMemory, magic).expect("failed to open store");

    // 2. Create mock header
    let header = BlockHeader {
        version: 1,
        prev_hash: BlockHash::ZERO,
        merkle_root: bitcrab_common::types::hash::Hash256::ZERO,
        time: 12345678,
        bits: 0x1d00ffff,
        nonce: 0,
    };
    let hash = header.block_hash();

    // 3. Store header (async)
    store
        .store_header(header.clone(), BlockHeight(0), Hash256::ZERO, true)
        .await
        .expect("failed to store header");

    // 4. Verify index retrieval (synchronous/concurrent)
    let index = store
        .get_block_index(&hash)
        .expect("failed to get index")
        .expect("block index missing");

    assert_eq!(index.height, BlockHeight(0));
    assert_eq!(index.header.block_hash(), hash);

    // 5. Verify best header update
    let headers_tip = store
        .get_headers_tip()
        .expect("failed to get headers tip")
        .expect("headers tip missing");
    assert_eq!(headers_tip, hash);

    // 6. Store full block (async)
    let raw_block = vec![0xAA; 100]; // Mock raw block data
    let pos = store
        .store_block(header, BlockHeight(0), Hash256::ZERO, raw_block.clone())
        .await
        .expect("failed to store block");

    assert_eq!(pos.file, 0);
    // Offset should be 8 (magic + size header)

    let block_tip = store
        .get_block_tip()
        .expect("failed to get block tip")
        .expect("block tip missing");
    assert_eq!(block_tip, hash);

    // 7. Read block back (direct concurrent read)
    let read_back = store
        .get_block(&hash)
        .expect("failed to get block")
        .expect("block data missing");

    assert_eq!(read_back, raw_block);

    drop(store);
    tokio::task::yield_now().await;
    std::fs::remove_dir_all(dir).ok();
}
