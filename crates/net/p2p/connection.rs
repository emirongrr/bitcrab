//! High-level connection helpers — thin wrappers over PeerManager.
//!
//! Bitcoin Core: CConnman helpers in src/net.cpp

use crate::p2p::{errors::P2pError, message::Magic, peer_manager::PeerManager};

/// Connect to a single signet peer and return a PeerManager.
pub async fn connect(addr: &str, magic: Magic) -> Result<PeerManager, P2pError> {
    let mut manager = PeerManager::new(magic);
    manager.connect(addr).await?;
    Ok(manager)
}