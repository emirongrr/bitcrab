//! ConnectionInitiatorActor: Proactively maintains the target peer count.

use std::time::Duration;
use tokio::time::interval;
use tracing::{info, debug};

use super::{
    actor::{Actor, ActorError, Context},
    peer_table::PeerTable,
    peer_manager::PeerManager,
};

/// Messages handled by the ConnectionInitiator actor.
pub enum InitiatorMessage {
    /// Check if we need to establish more outbound connections.
    CheckConnections,
}

pub struct ConnectionInitiator {
    peer_table: PeerTable,
    manager: std::sync::Arc<PeerManager>,
    target_outbound: usize,
}

impl ConnectionInitiator {
    pub fn new(peer_table: PeerTable, manager: std::sync::Arc<PeerManager>, target_outbound: usize) -> Self {
        Self {
            peer_table,
            manager,
            target_outbound,
        }
    }

    async fn fill_connections(&self) {
        let current_count = self.peer_table.get_peer_count().await.unwrap_or(0);
        if current_count >= self.target_outbound {
            return;
        }

        let needed = self.target_outbound - current_count;
        debug!("[initiator] current peers: {}, needed: {}", current_count, needed);

        for _ in 0..needed {
            if let Ok(Some(addr)) = self.peer_table.get_best_address().await {
                let mg = self.manager.clone();
                tokio::spawn(async move {
                    if let Err(e) = mg.connect_addr(addr).await {
                        debug!("[initiator] failed to connect to {}: {}", addr, e);
                    }
                });
            } else {
                break;
            }
        }
    }
}

impl Actor for ConnectionInitiator {
    type Message = InitiatorMessage;

    fn on_start(&mut self, ctx: &mut Context<Self>) -> impl std::future::Future<Output = Result<(), ActorError>> + Send {
        let handle = ctx.handle();
        async move {
            info!("[initiator] starting connection initiator");
            tokio::spawn(async move {
                let mut interval = interval(Duration::from_secs(30));
                loop {
                    interval.tick().await;
                    let _ = handle.cast(InitiatorMessage::CheckConnections).await;
                }
            });
            Ok(())
        }
    }

    fn handle(
        &mut self,
        msg: Self::Message,
        _ctx: &mut Context<Self>,
    ) -> impl std::future::Future<Output = Result<(), ActorError>> + Send {
        async move {
            match msg {
                InitiatorMessage::CheckConnections => {
                    self.fill_connections().await;
                }
            }
            Ok(())
        }
    }
}
