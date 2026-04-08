//! DispatcherActor: Routes internal P2P messages to the appropriate specialized actors.

use super::{
    actor::{Actor, ActorError, Context},
    messages::Message,
    peer::PeerHandle,
    peer_table::PeerTable,
    sync::{BlockDownloadMessage, HeaderSyncMessage, SyncManager},
};
use tracing::{debug, warn};

pub enum DispatchMessage {
    /// A new message received from a peer.
    PeerMessage(PeerHandle, Message),
}

pub struct DispatcherActor {
    peer_table: PeerTable,
    sync: SyncManager,
}

impl DispatcherActor {
    pub fn new(peer_table: PeerTable, sync: SyncManager) -> Self {
        Self { peer_table, sync }
    }
}

impl Actor for DispatcherActor {
    type Message = DispatchMessage;

    fn handle(
        &mut self,
        msg: Self::Message,
        _ctx: &mut Context<Self>,
    ) -> impl std::future::Future<Output = Result<(), ActorError>> + Send {
        async move {
            match msg {
                DispatchMessage::PeerMessage(handle, message) => {
                    match message {
                        Message::Addr(addr) => {
                            debug!(
                                "[dispatcher] routing Addr from {} to PeerTable",
                                handle.addr
                            );
                            let _ = self
                                .peer_table
                                .add_addresses(addr.addresses, handle.addr)
                                .await;
                        }
                        Message::GetAddr(_) => {
                            debug!(
                                "[dispatcher] routing GetAddr from {} to PeerTable",
                                handle.addr
                            );
                            match self.peer_table.get_addresses().await {
                                Ok(addresses) => {
                                    let _ = handle
                                        .send(Message::Addr(crate::p2p::messages::addr::Addr {
                                            addresses,
                                        }))
                                        .await;
                                }
                                Err(e) => warn!(
                                    "Failed to get addresses from table for {}: {}",
                                    handle.addr, e
                                ),
                            }
                        }

                        // Routing to Sync Layer
                        Message::Headers(headers) => {
                            let _ = self
                                .sync
                                .headers
                                .cast(HeaderSyncMessage::HeadersReceived(handle, headers))
                                .await;
                        }
                        Message::Block(block) => {
                            let _ = self
                                .sync
                                .blocks
                                .cast(BlockDownloadMessage::BlockReceived(handle, block))
                                .await;
                        }
                        Message::Inv(inv) => {
                            // Extract block hashes and forward to downloader
                            let block_hashes: Vec<_> = inv
                                .inventory
                                .iter()
                                .filter(|item| {
                                    item.inv_type == crate::p2p::messages::inv::InvType::Block
                                })
                                .map(|item| item.hash)
                                .collect();

                            if !block_hashes.is_empty() {
                                let _ = self
                                    .sync
                                    .blocks
                                    .cast(BlockDownloadMessage::DownloadBlocks(block_hashes))
                                    .await;
                            }
                        }

                        // Default: unhandled
                        other => {
                            debug!(
                                "[dispatcher] received {} from {} (unhandled)",
                                other.command().name(),
                                handle.addr
                            );
                        }
                    }
                }
            }
            Ok(())
        }
    }
}
