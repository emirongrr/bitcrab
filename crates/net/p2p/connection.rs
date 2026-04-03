//! High-level connection helpers — thin wrappers over PeerManager.
//!
//! Bitcoin Core: CConnman helpers in src/net.cpp

use tokio::sync::mpsc::Receiver;
use crate::p2p::{errors::P2pError, message::Magic, peer_manager::PeerManager, peer::Peer, messages::Message};

/// Connect to a single signet peer and return a PeerManager, Peer handle and incoming message receiver.
pub async fn connect(addr: &str, magic: Magic) -> Result<(PeerManager, Peer, Receiver<Message>), P2pError> {
    let manager = PeerManager::new(magic);
    let (peer, rx) = manager.connect(addr).await?;
    Ok((manager, peer, rx))
}
