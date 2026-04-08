//! # bitcrab RPC
//!
//! This crate implements the Bitcoin-compatible JSON-RPC API.
//! Matches Ethrex architecture for trait-based handlers and namespace isolation.

pub mod blockchain;
pub mod net;
pub mod rpc;
pub mod types;
pub mod utils;

pub use rpc::{start_api, RpcApiContext, RpcHandler, RpcRequestWrapper};
pub use utils::{RpcErr, RpcNamespace};
