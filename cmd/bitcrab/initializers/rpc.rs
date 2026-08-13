//! RPC initialization logic for the bitcrab binary.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{error, info};

use bitcrab_net::p2p::connman::Connman;
use bitcrab_rpc::rpc::RpcNodeProvider;

/// Starts the JSON-RPC server on a background task.
pub fn init_rpc(
    addr: SocketAddr,
    node: Arc<dyn RpcNodeProvider>,
    p2p: Arc<Connman>,
    tracker: &TaskTracker,
    cancel_token: CancellationToken,
) {
    let rpc_ctx = bitcrab_rpc::rpc::RpcApiContext { node, p2p };

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
