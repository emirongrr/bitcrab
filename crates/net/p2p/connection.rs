//! High-level connection helpers — thin wrappers over PeerManager.
//!
//! Bitcoin Core: CConnman helpers in src/net.cpp

use tokio::sync::mpsc::Receiver;
use crate::p2p::{
    errors::P2pError, 
    message::Magic, 
    peer_manager::PeerManager, 
    peer::PeerHandle, 
    peer_table::PeerTable,
    addr_man::AddrMan,
    messages::Message
};

/// Connect to a single signet peer and return a PeerManager, Peer handle and incoming message receiver.
pub async fn connect(addr: &str, magic: Magic) -> Result<(PeerManager, PeerHandle, Receiver<Message>), P2pError> {
    let table = PeerTable::new(AddrMan::new());
    let manager = PeerManager::new(magic, table);
    let (peer, rx) = manager.connect(addr).await?;
    Ok((manager, peer, rx))
}

