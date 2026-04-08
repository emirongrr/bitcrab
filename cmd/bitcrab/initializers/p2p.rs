//! P2P Networking initialization logic for the bitcrab binary.

use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{info, error};

use bitcrab_common::types::hash::BlockHash;
use bitcrab_common::types::block::BlockHeight;
use bitcrab_net::p2p::{
    addr_man::AddrMan, 
    dispatcher::DispatcherActor, 
    message::Magic,
    peer_manager::PeerManager, 
    peer_table::PeerTable, 
    sync::{SyncManager, HeaderSyncMessage},
    network::{run_p2p_maintenance, NetworkConfig},
    actor::Actor,
};
use bitcrab_storage::Store;

pub struct P2PContext {
    pub peer_manager: Arc<PeerManager>,
    pub sync_manager: SyncManager,
}

/// Initializes the full networking stack.
pub fn init_p2p(
    magic: Magic,
    store: Store,
    block_notifier: mpsc::Sender<(BlockHash, BlockHeight)>,
    tracker: &TaskTracker,
    cancel_token: CancellationToken,
) -> P2PContext {
    info!("[init] starting networking stack for network: {}", magic);

    // 1. Data Structures
    let table = PeerTable::new(AddrMan::new());
    
    // 2. Synchronization Layer
    let sync = SyncManager::new(store.clone(), table.clone(), Some(block_notifier));
    
    // 3. Routing Layer
    let dispatcher = DispatcherActor::new(table.clone(), sync.clone()).spawn();
    
    // 4. Peer Management
    let peer_manager = Arc::new(PeerManager::new(magic, table, dispatcher).with_sync(sync.clone()));

    // 5. P2P Maintenance Task
    let p2p_manager = Arc::clone(&peer_manager);
    let p2p_config = match magic {
        Magic::Mainnet => NetworkConfig::mainnet(),
        Magic::Signet => NetworkConfig::signet(),
        _ => NetworkConfig::signet(),
    };

    let p2p_cancel = cancel_token.clone();
    tracker.spawn(async move {
        tokio::select! {
            res = run_p2p_maintenance(p2p_manager, p2p_config) => {
                if let Err(e) = res {
                    error!("P2P maintenance loop failed: {}", e);
                }
            }
            _ = p2p_cancel.cancelled() => {
                info!("[net] P2P networking shutting down");
            }
        }
    });

    // 6. Optimization: Trigger immediate header sync when first peer connects
    // This is handled by the HeaderSyncActor's maintenance loop, but we could trigger it pro-actively here
    // if we added a PeerConnected message to the SyncManager. (To be added if requested).

    P2PContext {
        peer_manager,
        sync_manager: sync,
    }
}
