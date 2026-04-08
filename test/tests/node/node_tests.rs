//! bitcrab-node integration tests.

use bitcrab_common::types::{
    block::{BlockHeader, BlockHeight},
    hash::{BlockHash, Hash256},
};
use bitcrab_net::p2p::message::Magic;
use bitcrab_node::Node;

fn test_header(nonce: u32) -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_hash: BlockHash::zero(),
        merkle_root: Hash256::zero(),
        time: 1_700_000_000,
        bits: 0x1d00ffff,
        nonce,
    }
}

#[tokio::test]
async fn node_in_memory_starts_empty() {
    let node = Node::in_memory(Magic::Regtest).unwrap();
    assert!(node.best_hash().unwrap().is_none());
    assert!(node.best_height().unwrap().is_none());
}

#[tokio::test]
async fn store_header_updates_best() {
    let mut node = Node::in_memory(Magic::Regtest).unwrap();
    let header = test_header(1);
    let hash = header.block_hash();

    node.store
        .store_header(&header, BlockHeight(0), true)
        .unwrap();

    assert_eq!(node.best_hash().unwrap(), Some(hash));
    assert_eq!(node.best_height().unwrap(), Some(BlockHeight(0)));
}

#[tokio::test]
async fn store_multiple_headers_height_tracks() {
    let mut node = Node::in_memory(Magic::Regtest).unwrap();

    for i in 0..5u32 {
        let header = test_header(i);
        node.store
            .store_header(&header, BlockHeight(i), i == 4)
            .unwrap();
    }

    assert_eq!(node.best_height().unwrap(), Some(BlockHeight(4)));
}
