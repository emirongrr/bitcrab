use bitcrab_net::p2p::peer_manager::PeerManager;
use bitcrab_storage::Store;
use std::sync::Arc;

/// The shared context for all RPC handlers.
/// Holds handles to node services (Storage, Networking, etc).
#[derive(Clone)]
pub struct RpcContext {
    pub store: Store,
    pub peer_manager: Arc<PeerManager>,
}

impl RpcContext {
    pub fn new(store: Store, peer_manager: Arc<PeerManager>) -> Self {
        Self {
            store,
            peer_manager,
        }
    }
}
