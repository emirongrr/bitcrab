use std::net::SocketAddr;
use std::sync::Arc;
use axum::{
    routing::post,
    extract::State,
    Json, Router,
};
use tracing::{info, error};

pub mod context;
pub mod methods;

use crate::context::RpcContext;
use crate::methods::{RpcRequest, RpcResponse, dispatch};

/// Starts the Bitcoin-compatible RPC server.
pub async fn start_rpc_server(ctx: RpcContext, addr: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Router::new()
        .route("/", post(handle_rpc))
        .with_state(ctx);

    info!("RPC server starting on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn handle_rpc(
    State(ctx): State<RpcContext>,
    Json(req): Json<RpcRequest>,
) -> Json<RpcResponse> {
    tracing::debug!("RPC call: {}", req.method);
    let resp = dispatch(req, ctx).await;
    Json(resp)
}
