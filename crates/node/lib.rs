//! Bitcoin node — orchestrates net and storage.

pub mod node;
pub use node::{Node, NodeError, init_node, NodeConfig, NodeHandles};