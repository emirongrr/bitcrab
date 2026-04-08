//! High-level connection helpers — thin wrappers over PeerManager.
//!
//! Bitcoin Core: CConnman helpers in src/net.cpp

use crate::p2p::{
    addr_man::AddrMan, errors::P2pError, message::Magic, messages::Message, peer::PeerHandle,
    peer_manager::PeerManager, peer_table::PeerTable,
};
use tokio::sync::mpsc::Receiver;

/// Connect to a single signet peer and return a PeerManager, Peer handle and incoming message receiver.
pub async fn connect(
    addr: &str,
    magic: Magic,
) -> Result<(PeerManager, PeerHandle, Receiver<Message>), P2pError> {
    let table = PeerTable::new(AddrMan::new());
    let manager = PeerManager::new(magic, table);
    let (peer, rx) = manager.connect(addr).await?;
    Ok((manager, peer, rx))
}
