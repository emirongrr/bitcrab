//! RPC initialization logic for the bitcrab binary.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{info, error};

use bitcrab_storage::Store;
use bitcrab_net::p2p::peer_manager::PeerManager;

/// Starts the JSON-RPC server on a background task.
pub fn init_rpc(
    addr: SocketAddr,
    store: Store,
    peer_manager: Arc<PeerManager>,
    tracker: &TaskTracker,
    cancel_token: CancellationToken,
) {
    let rpc_ctx = bitcrab_rpc::RpcApiContext {
        store,
        peer_manager,
    };

    tracker.spawn(async move {
        tokio::select! {
            res = bitcrab_rpc::start_api(rpc_ctx, addr) => {
                if let Err(e) = res {
                    error!("RPC server failed: {}", e);
                }
            }
            _ = cancel_token.cancelled() => {
                info!("[rpc] shutting down");
            }
        }
    });
}
