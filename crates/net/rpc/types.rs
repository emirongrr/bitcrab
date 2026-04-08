use crate::utils::{RpcErrorMetadata, RpcRequestId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A successful JSON-RPC 2.0 response.
#[derive(Serialize, Deserialize, Debug)]
pub struct RpcSuccessResponse {
    pub id: RpcRequestId,
    pub jsonrpc: String,
    pub result: Value,
}

/// An error JSON-RPC 2.0 response.
#[derive(Serialize, Deserialize, Debug)]
pub struct RpcErrorResponse {
    pub id: RpcRequestId,
    pub jsonrpc: String,
    pub error: RpcErrorMetadata,
}

/// A JSON-RPC 2.0 response, either success or error.
#[derive(Deserialize, Serialize, Debug)]
#[serde(untagged)]
pub enum RpcResponse {
    Success(RpcSuccessResponse),
    Error(RpcErrorResponse),
}

impl RpcResponse {
    pub fn success(id: RpcRequestId, result: Value) -> Self {
        RpcResponse::Success(RpcSuccessResponse {
            id,
            jsonrpc: "2.0".to_string(),
            result,
        })
    }

    pub fn error(id: RpcRequestId, error: RpcErrorMetadata) -> Self {
        RpcResponse::Error(RpcErrorResponse {
            id,
            jsonrpc: "2.0".to_string(),
            error,
        })
    }
}
