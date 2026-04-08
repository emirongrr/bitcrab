pub mod p2p;
pub mod rpc;
pub mod storage;

use std::path::PathBuf;
use bitcrab_net::p2p::message::Magic;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use bitcrab_storage::Store;

pub use p2p::{init_p2p, P2PContext};
pub use rpc::init_rpc;
pub use storage::{init_store, compute_effective_datadir};
use bitcrab_net::p2p::actor::Actor;

pub async fn init_node_service(
    datadir: Option<PathBuf>,
    magic: Magic,
    rpc_addr: Option<std::net::SocketAddr>,
) -> eyre::Result<(PathBuf, CancellationToken, TaskTracker, Store)> {
    let effective_datadir = compute_effective_datadir(&datadir, magic);
    
    let cancel_token = CancellationToken::new();
    let tracker = TaskTracker::new();
    
    // 1. Storage
    let store = init_store(&effective_datadir, magic).await?;
    
    // 2. Consensus Actor (Chainstate)
    let (block_notify_tx, mut block_notify_rx) = tokio::sync::mpsc::channel(1024);
    let chain_manager = bitcrab_consensus::ChainstateManager::new(store.clone()).spawn();
    
    let chain_handle = chain_manager.clone();
    tracker.spawn(async move {
        while let Some((hash, height)) = block_notify_rx.recv().await {
            let _ = chain_handle
                .cast(bitcrab_consensus::ChainstateMessage::BlockDownloaded(
                    hash, height,
                ))
                .await;
        }
    });

    // 3. P2P Stack
    let p2p_ctx = init_p2p(
        magic, 
        store.clone(), 
        block_notify_tx, 
        &tracker, 
        cancel_token.clone()
    );

    // 4. RPC
    if let Some(addr) = rpc_addr {
        init_rpc(
            addr, 
            store.clone(), 
            p2p_ctx.peer_manager, 
            &tracker, 
            cancel_token.clone()
        );
    }

    tracker.close();

    Ok((effective_datadir, cancel_token, tracker, store))
}
