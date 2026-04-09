//! Utility types and error handling for JSON-RPC.
//!
//! Matches Bitcoin Core and Ethrex patterns for error mapping and namespace resolution.

use bitcrab_storage::error::StoreError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Error type for JSON-RPC method failures.
#[derive(Debug, thiserror::Error)]
pub enum RpcErr {
    #[error("Method not found: {0}")]
    MethodNotFound(String),
    #[error("Wrong parameter: {0}")]
    WrongParam(String),
    #[error("Invalid params: {0}")]
    BadParams(String),
    #[error("Missing parameter: {0}")]
    MissingParam(String),
    #[error("Internal Error: {0}")]
    Internal(String),
}

/// Metadata for JSON-RPC error responses.
#[derive(Serialize, Deserialize, Debug)]
pub struct RpcErrorMetadata {
    pub code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    pub message: String,
}

impl From<RpcErr> for RpcErrorMetadata {
    fn from(value: RpcErr) -> Self {
        match value {
            RpcErr::MethodNotFound(bad_method) => RpcErrorMetadata {
                code: -32601,
                data: None,
                message: format!("Method not found: {bad_method}"),
            },
            RpcErr::WrongParam(field) => RpcErrorMetadata {
                code: -32602,
                data: None,
                message: format!("Field '{field}' is incorrect or has an unknown format"),
            },
            RpcErr::BadParams(context) => RpcErrorMetadata {
                code: -32602, // Standard JSON-RPC Invalid Params
                data: None,
                message: format!("Invalid params: {context}"),
            },
            RpcErr::MissingParam(parameter_name) => RpcErrorMetadata {
                code: -32602,
                data: None,
                message: format!("Expected parameter: {parameter_name} is missing"),
            },
            RpcErr::Internal(context) => RpcErrorMetadata {
                code: -32603,
                data: None,
                message: format!("Internal Error: {context}"),
            },
        }
    }
}

impl From<StoreError> for RpcErr {
    fn from(value: StoreError) -> Self {
        RpcErr::Internal(value.to_string())
    }
}

/// JSON-RPC method namespace.
pub enum RpcNamespace {
    Blockchain,
    Net,
    Mining,
    Admin,
}

/// A parsed JSON-RPC 2.0 request.
#[derive(Serialize, Deserialize, Debug)]
pub struct RpcRequest {
    pub id: RpcRequestId,
    pub jsonrpc: String,
    pub method: String,
    pub params: Option<Vec<Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum RpcRequestId {
    Number(u64),
    String(String),
    Null,
}

impl RpcRequest {
    pub fn namespace(&self) -> Result<RpcNamespace, RpcErr> {
        // Bitcoin-style: methods like 'getblockchaininfo' don't have '_'
        // We will map based on string matches or prefixes
        let m = self.method.as_str();
        if m.contains("blockchain") || m.contains("block") {
            Ok(RpcNamespace::Blockchain)
        } else if m.contains("network")
            || m.contains("peer")
            || m.contains("connection")
        {
            Ok(RpcNamespace::Net)
        } else {
            Ok(RpcNamespace::Net)
        }
    }
}

impl Default for RpcRequestId {
    fn default() -> Self {
        RpcRequestId::Number(1)
    }
}
