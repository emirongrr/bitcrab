//! ConnectionInitiatorActor: Proactively maintains the target peer count.

use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, info, error};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::net::SocketAddr;

use super::{
    actor::{Actor, ActorError, Context},
    peer_manager::PeerManager,
    peer_table::PeerTable,
};

/// Messages handled by the ConnectionInitiator actor.
pub enum InitiatorMessage {
    /// Check if we need to establish more outbound connections.
    CheckConnections,
}

pub struct ConnectionInitiator {
    peer_table: PeerTable,
    manager: Arc<PeerManager>,
    target_outbound: usize,
    pending_attempts: Arc<Mutex<HashSet<SocketAddr>>>,
}

impl ConnectionInitiator {
    pub fn new(
        peer_table: PeerTable,
        manager: Arc<PeerManager>,
        target_outbound: usize,
    ) -> Self {
        Self {
            peer_table,
            manager,
            target_outbound,
            pending_attempts: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    async fn fill_connections(&self) {
        let current_count = self.peer_table.get_peer_count().await.unwrap_or(0);
        let pending_count = self.pending_attempts.lock().unwrap().len();
        
        if current_count + pending_count >= self.target_outbound {
            return;
        }

        let needed = self.target_outbound - (current_count + pending_count);
        debug!(
            "[initiator] current: {}, pending: {}, target: {}, needed: {}",
            current_count, pending_count, self.target_outbound, needed
        );

        for _ in 0..needed {
            let pending_list: Vec<SocketAddr> = self.pending_attempts.lock().unwrap().iter().cloned().collect();
            
            if let Ok(Some(addr)) = self.peer_table.get_best_address(pending_list).await {
                // Mark as pending
                self.pending_attempts.lock().unwrap().insert(addr);
                
                let mg = self.manager.clone();
                let pending_tracker = self.pending_attempts.clone();
                
                tokio::spawn(async move {
                    let res = mg.connect_addr(addr).await;
                    // Remove from pending after attempt (success or failure)
                    pending_tracker.lock().unwrap().remove(&addr);
                    
                    if let Err(e) = res {
                        debug!("[initiator] failed to connect to {}: {}", addr, e);
                    } else {
                        info!("[initiator] successfully connected to {}", addr);
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

    fn on_start(
        &mut self,
        ctx: &mut Context<Self>,
    ) -> impl std::future::Future<Output = Result<(), ActorError>> + Send {
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
