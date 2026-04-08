//! Bitcoin node — orchestrates net and storage.

pub mod node;
pub use node::{init_node, Node, NodeConfig, NodeError, NodeHandles};
