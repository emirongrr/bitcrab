//! P2P Networking initialization logic for the bitcrab binary.

use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{error, info};

use bitcrab_common::ChainType;
use bitcrab_net::p2p::peer_manager::ValidationInterface;
use bitcrab_net::p2p::{
    addr_man::AddrMan, connman::Connman, network::run_p2p_maintenance, peer_manager::PeerManager,
    peer_table::PeerTable, sync::block_downloader::BlockDownloader, sync::SyncManager,
    sync::SyncProvider,
};
use bitcrab_node::Blockchain;
use bitcrab_storage::Store;

pub struct P2PContext {
    pub p2p: Arc<Connman>,
    pub sync_manager: Arc<SyncManager>,
    pub peer_manager: Arc<PeerManager>,
}

/// Initializes the full networking stack.
pub fn init_p2p(
    chain: ChainType,
    _store: Store,
    blockchain: Arc<Blockchain>,
    tracker: &TaskTracker,
    cancel_token: CancellationToken,
) -> P2PContext {
    let params = chain.chain_params();
    let magic = params.magic;
    info!("[init] starting networking stack for chain: {}", chain);

    // 1. Data Structures
    let peer_table = PeerTable::new(AddrMan::new());

    // 2. Synchronization Layer
    let (headers_tip, headers_height) =
        bitcrab_net::p2p::sync::SyncProvider::get_headers_tip(blockchain.as_ref());
    let (blocks_tip, blocks_height) =
        bitcrab_net::p2p::sync::SyncProvider::get_blocks_tip(blockchain.as_ref());

    info!(
        "[init] Resuming sync: headers at height {}, blocks at height {}",
        headers_height, blocks_height
    );

    // 2.3 Load timestamp for IBD detection
    let last_header_time = if !headers_tip.is_zero() {
        blockchain
            .get_block_index(&headers_tip)
            .map(|i| i.header.time as u64)
            .unwrap_or(0)
    } else {
        0
    };

    let sync = Arc::new(SyncManager::with_tips(
        headers_tip,
        headers_height,
        blocks_tip,
        blocks_height,
        last_header_time,
    ));

    // 3. Peer Manager (High-level Protocol/Validation)
    let peer_manager = Arc::new(PeerManager::new(
        peer_table.clone(),
        blockchain.clone() as Arc<dyn ValidationInterface>,
        sync.clone(),
    ));

    // 4. P2P Service (Low-level Networking)
    let p2p = Arc::new(Connman::new(
        magic,
        peer_table.clone(),
        peer_manager.clone(),
    ));

    // 5. P2P Maintenance Task
    let p2p_maintenance = Arc::clone(&p2p);

    let p2p_cancel = cancel_token.clone();
    tracker.spawn(async move {
        tokio::select! {
            res = run_p2p_maintenance(p2p_maintenance, chain) => {
                if let Err(e) = res {
                    error!("P2P maintenance loop failed: {}", e);
                }
            }
            _ = p2p_cancel.cancelled() => {
                info!("[net] P2P networking shutting down");
            }
        }
    });

    // 6. Block Downloader task
    let downloader = BlockDownloader::new(peer_table.clone(), sync.clone(), blockchain);
    let downloader_cancel = cancel_token.clone();
    tracker.spawn(async move {
        tokio::select! {
            _ = downloader.start() => {}
            _ = downloader_cancel.cancelled() => {
                info!("[sync] Block Downloader shutting down");
            }
        }
    });

    P2PContext {
        p2p,
        sync_manager: sync,
        peer_manager,
    }
}
