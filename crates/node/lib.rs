//! Bitcoin node — orchestrates net and storage.

pub mod node;
pub mod consensus;
pub use node::{init_node, Node, NodeConfig, NodeError, NodeHandles};
