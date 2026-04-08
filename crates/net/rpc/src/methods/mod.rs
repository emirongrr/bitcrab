use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod blockchain;
pub mod network;

#[derive(Debug, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: Option<String>,
    pub id: Value,
    pub method: String,
    pub params: Option<Vec<Value>>,
}

#[derive(Debug, Serialize)]
pub struct RpcResponse {
    pub jsonrpc: String,
    pub result: Option<Value>,
    pub error: Option<RpcError>,
    pub id: Value,
}

#[derive(Debug, Serialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

impl RpcResponse {
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    pub fn error(id: Value, code: i32, message: String) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(RpcError { code, message }),
            id,
        }
    }
}

pub async fn dispatch(req: RpcRequest, ctx: crate::context::RpcContext) -> RpcResponse {
    let id = req.id.clone();
    let result = match req.method.as_str() {
        "getblockchaininfo"  => blockchain::get_blockchain_info(ctx).await,
        "getnetworkinfo"     => network::get_network_info(ctx).await,
        "getpeerinfo"        => network::get_peer_info(ctx).await,
        "getconnectioncount" => network::get_connection_count(ctx).await,
        _ => Err(RpcError {
            code: -32601,
            message: format!("Method not found: {}", req.method),
        }),
    };

    match result {
        Ok(val) => RpcResponse::success(id, val),
        Err(err) => RpcResponse {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(err),
            id,
        },
    }
}

