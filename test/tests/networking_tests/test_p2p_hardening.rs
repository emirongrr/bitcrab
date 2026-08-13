use bitcrab_common::types::hash::BlockHash;
use bitcrab_net::p2p::sync::SyncManager;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::test]
async fn test_ibd_detection_logic_robust() {
    let sync = SyncManager::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Scenario 1: Fresh node (no blocks) -> IBD
    assert!(sync.is_ibd(), "Empty node must be in IBD");

    // Scenario 2: Node with recent block (e.g., 5 mins ago) -> NOT IBD
    sync.update_headers_tip(BlockHash::ZERO, 0, now - 300);
    assert!(!sync.is_ibd(), "Recent tip should clear IBD");

    // Scenario 3: Node with old block (e.g., 2 days ago) -> IBD
    sync.update_headers_tip(BlockHash::ZERO, 0, now - 172800);
    assert!(sync.is_ibd(), "Old tip (2d) must trigger IBD");

    // Scenario 4: Tip is okay but manual sync is active -> IBD
    sync.update_headers_tip(BlockHash::ZERO, 0, now - 300);
    sync.set_syncing(true);
    assert!(sync.is_ibd(), "Manual syncing override must trigger IBD");
}
