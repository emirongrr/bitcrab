//! Integration test for end-to-end consensus synchronization.
//! 
//! Verifies that blocks arriving via the sync notification channel are
//! correctly validated and connected to the tip.

use bitcrab_common::types::{
    block::{Block, BlockHeader, BlockHeight},
    hash::{BlockHash, Hash256},
    transaction::{Transaction, TxIn, TxOut, OutPoint},
    amount::Amount,
};
use bitcrab_net::p2p::message::Magic;
use bitcrab_node::{init_node, NodeConfig};

fn create_block(prev_hash: BlockHash, height: u32, txs: Vec<Transaction>) -> Block {
    let mut header = BlockHeader {
        version: 1,
        prev_hash,
        merkle_root: Hash256::zero(),
        time: 1_700_000_000 + (height * 600),
        bits: 0x1d00ffff,
        nonce: 0,
    };
    
    let block_without_root = Block::new(header.clone(), txs);
    header.merkle_root = block_without_root.compute_merkle_root();
    
    Block::new(header, block_without_root.transactions)
}

fn create_coinbase(height: u32) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: OutPoint {
                txid: Hash256::zero().into(),
                vout: 0xffff_ffff,
            },
            script_sig: vec![], // BIP34 height or dummy
            sequence: 0xffff_ffff,
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50_000_000_00),
            script_pubkey: vec![], // OP_TRUE or dummy
        }],
        lock_time: 0,
    }
}

#[tokio::test]
async fn test_sequential_consensus_sync() {
    let config = NodeConfig {
        magic: Magic::Regtest,
        rpc_addr: None,
        data_dir: None, // In-memory
    };
    
    let handles = init_node(config).await.expect("Failed to init node");
    let store = handles.node.store.clone();
    
    // 1. Create a chain of 3 blocks
    let b0 = create_block(BlockHash::zero(), 0, vec![create_coinbase(0)]);
    let b1 = create_block(b0.header.block_hash(), 1, vec![create_coinbase(1)]);
    let b2 = create_block(b1.header.block_hash(), 2, vec![create_coinbase(2)]);
    
    // 2. Mock: Headers are already indexed (Simulating HeaderSyncActor)
    for (i, b) in [&b0, &b1, &b2].iter().enumerate() {
        store.store_header(b.header.clone(), BlockHeight(i as u32), i == 2).expect("Store header failed");
    }
    
    // 3. Mock: Blocks arrive out of order (b1, then b2, then b0)
    // Persist to disk first (Simulating BlockDownloadActor behavior)
    use bitcrab_common::wire::encode::{BitcoinEncode, Encoder};
    for (i, b) in [(&b1, 1), (&b2, 2), (&b0, 0)] {
        let raw = b.encode(Encoder::new()).finish();
        store.store_block(b.header.clone(), BlockHeight(i), raw).await.expect("Store block failed");
    }
    
    // 4. Notify arrival in out-of-order sequence
    handles.block_notifier.send((b1.header.block_hash(), BlockHeight(1))).await.unwrap();
    handles.block_notifier.send((b2.header.block_hash(), BlockHeight(2))).await.unwrap();
    
    // Tip should still be null (waiting for b0)
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    assert!(handles.node.best_height().unwrap().is_none());
    
    // Connect b0
    handles.block_notifier.send((b0.header.block_hash(), BlockHeight(0))).await.unwrap();
    
    // Tip should eventually reach height 2
    let mut tip = BlockHeight(0);
    for _ in 0..10 {
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        if let Some(h) = handles.node.best_height().unwrap() {
            tip = h;
            if h == BlockHeight(2) { break; }
        }
    }
    
    assert_eq!(tip, BlockHeight(2));
    assert_eq!(handles.node.best_hash().unwrap(), Some(b2.header.block_hash()));
    
    // Shutdown
    handles.cancel_token.cancel();
}
