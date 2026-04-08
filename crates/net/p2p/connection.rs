//! High-level connection helpers — thin wrappers over PeerManager.
//!
//! Bitcoin Core: CConnman helpers in src/net.cpp

use crate::p2p::{
    actor::Actor, addr_man::AddrMan, dispatcher::DispatcherActor, errors::P2pError, message::Magic,
    peer::PeerHandle, peer_manager::PeerManager, peer_table::PeerTable, sync::SyncManager,
};

/// Connect to a single signet peer and return a PeerManager and Peer handle.
///
/// Note: This is a legacy helper. For full node operations, use Node::init().
pub async fn connect(addr: &str, magic: Magic) -> Result<(PeerManager, PeerHandle), P2pError> {
    let table = PeerTable::new(AddrMan::new());

    // Legacy connect doesn't need a real sync manager or block notifier
    let sync = SyncManager::new(
        bitcrab_storage::Store::in_memory(magic).unwrap(),
        table.clone(),
        None,
    );
    let dispatcher = DispatcherActor::new(table.clone(), sync).spawn();

    let manager = PeerManager::new(magic, table, dispatcher);
    let peer = manager.connect(addr).await?;

    Ok((manager, peer))
}
