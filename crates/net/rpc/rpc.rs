use axum::{extract::State, routing::post, Json, Router};
use serde::Deserialize;
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, info};

use crate::types::RpcResponse;
use crate::utils::{RpcErr, RpcErrorMetadata, RpcNamespace, RpcRequest};
use bitcrab_net::p2p::peer_manager::PeerManager;
use bitcrab_storage::Store;

/// Dependencies that RPC handlers need to process requests.
#[derive(Clone)]
pub struct RpcApiContext {
    pub store: Store,
    pub peer_manager: Arc<PeerManager>,
}

/// Trait for implementing JSON-RPC method handlers.
#[allow(async_fn_in_trait)]
pub trait RpcHandler: Sized {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr>;

    async fn call(req: &RpcRequest, context: RpcApiContext) -> Result<Value, RpcErr> {
        let request = Self::parse(&req.params)?;
        request.handle(context).await
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr>;
}

/// Wrapper for single or batch requests.
#[derive(Deserialize)]
#[serde(untagged)]
pub enum RpcRequestWrapper {
    Single(RpcRequest),
    Multiple(Vec<RpcRequest>),
}

/// Starts the JSON-RPC API server.
pub async fn start_api(
    ctx: RpcApiContext,
    addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Router::new()
        .route("/", post(handle_http_request))
        .with_state(ctx);

    info!("Starting JSON-RPC server at http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn handle_http_request(
    State(ctx): State<RpcApiContext>,
    Json(wrapper): Json<RpcRequestWrapper>,
) -> Json<Value> {
    match wrapper {
        RpcRequestWrapper::Single(req) => {
            let res = map_http_requests(&req, ctx).await;
            Json(rpc_response(req, res))
        }
        RpcRequestWrapper::Multiple(reqs) => {
            let mut resps = Vec::new();
            for req in reqs {
                let res = map_http_requests(&req, ctx.clone()).await;
                resps.push(rpc_response(req, res));
            }
            Json(serde_json::to_value(resps).unwrap())
        }
    }
}

pub async fn map_http_requests(req: &RpcRequest, context: RpcApiContext) -> Result<Value, RpcErr> {
    match req.namespace() {
        Ok(RpcNamespace::Blockchain) => map_blockchain_requests(req, context).await,
        Ok(RpcNamespace::Net) => map_net_requests(req, context).await,
        _ => Err(RpcErr::MethodNotFound(req.method.clone())),
    }
}

pub async fn map_blockchain_requests(
    req: &RpcRequest,
    context: RpcApiContext,
) -> Result<Value, RpcErr> {
    use crate::blockchain::GetBlockchainInfoRequest;
    match req.method.as_str() {
        "getblockchaininfo" => GetBlockchainInfoRequest::call(req, context).await,
        _ => Err(RpcErr::MethodNotFound(req.method.clone())),
    }
}

pub async fn map_net_requests(req: &RpcRequest, context: RpcApiContext) -> Result<Value, RpcErr> {
    use crate::net::{GetConnectionCountRequest, GetNetworkInfoRequest, GetPeerInfoRequest};
    match req.method.as_str() {
        "getnetworkinfo" => GetNetworkInfoRequest::call(req, context).await,
        "getpeerinfo" => GetPeerInfoRequest::call(req, context).await,
        "getconnectioncount" => GetConnectionCountRequest::call(req, context).await,
        _ => Err(RpcErr::MethodNotFound(req.method.clone())),
    }
}

pub fn rpc_response(req: RpcRequest, res: Result<Value, RpcErr>) -> Value {
    let id = req.id;
    match res {
        Ok(result) => serde_json::to_value(RpcResponse::success(id, result)).unwrap(),
        Err(err) => {
            let metadata: RpcErrorMetadata = err.into();
            serde_json::to_value(RpcResponse::error(id, metadata)).unwrap()
        }
    }
}
