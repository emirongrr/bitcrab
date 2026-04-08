//! Integration tests for storage layer.
//!
//! Tests combining multiple components: Handle, Worker, and BlockFiles.

use bitcrab_common::types::block::{BlockHeader, BlockHeight};
use bitcrab_common::types::hash::BlockHash;
use bitcrab_storage::{Magic, Store};

#[tokio::test]
async fn storage_integration_basic_flow() {
    let magic = Magic::Regtest;
    // 1. Initialize in-memory store (spawns worker internally)
    let store = Store::in_memory(magic).expect("failed to open store");

    // 2. Create mock header
    let header = BlockHeader {
        version: 1,
        prev_block: BlockHash::zero(),
        merkle_root: BlockHash::zero(),
        time: 12345678,
        bits: 0x1d00ffff,
        nonce: 0,
    };
    let hash = header.block_hash();

    // 3. Store header (async)
    store
        .store_header(header.clone(), BlockHeight(0), true)
        .await
        .expect("failed to store header");

    // 4. Verify index retrieval (synchronous/concurrent)
    let index = store
        .get_block_index(&hash)
        .expect("failed to get index")
        .expect("block index missing");

    assert_eq!(index.height, BlockHeight(0));
    assert_eq!(index.header.block_hash(), hash);

    // 5. Verify best block update
    let best = store
        .get_best_block()
        .expect("failed to get best block")
        .expect("best block missing");
    assert_eq!(best, hash);

    // 6. Store full block (async)
    let raw_block = vec![0xAA; 100]; // Mock raw block data
    let pos = store
        .store_block(header, BlockHeight(0), raw_block.clone())
        .await
        .expect("failed to store block");

    assert_eq!(pos.file, 0);
    // Offset should be 8 (magic + size header)

    // 7. Read block back (direct concurrent read)
    let read_back = store
        .get_block(&hash)
        .expect("failed to get block")
        .expect("block data missing");

    assert_eq!(read_back, raw_block);
}
