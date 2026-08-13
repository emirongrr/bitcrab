//! Maintains Bitcoin Core-style automatic outbound connection quotas.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::time::interval;
use tracing::{debug, info};

use super::{
    connman::Connman,
    net_types::{
        ConnectionType, MAX_BLOCK_RELAY_ONLY_CONNECTIONS, MAX_FEELER_CONNECTIONS,
        MAX_OUTBOUND_FULL_RELAY_CONNECTIONS,
    },
    peer_table::PeerTable,
};

pub struct ConnectionInitiator {
    peer_table: PeerTable,
    p2p: Arc<Connman>,
    pending_attempts: Arc<Mutex<HashMap<SocketAddr, ConnectionType>>>,
}

impl ConnectionInitiator {
    pub fn new(peer_table: PeerTable, p2p: Arc<Connman>) -> Self {
        Self {
            peer_table,
            p2p,
            pending_attempts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn spawn(self) {
        let arc_self = Arc::new(self);
        info!(
            "[initiator] starting connection initiator ({} full-relay, {} block-relay-only)",
            MAX_OUTBOUND_FULL_RELAY_CONNECTIONS, MAX_BLOCK_RELAY_ONLY_CONNECTIONS
        );

        let connection_loop = arc_self.clone();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                connection_loop.fill_connections().await;
            }
        });

        tokio::spawn(async move {
            let mut feeler_interval = interval(Duration::from_secs(120));
            loop {
                feeler_interval.tick().await;
                arc_self.run_feeler().await;
            }
        });
    }

    async fn run_feeler(&self) {
        let active = self
            .peer_table
            .get_peer_count_by_type(ConnectionType::Feeler)
            .await;
        let pending = self.pending_count(ConnectionType::Feeler);
        if active + pending >= MAX_FEELER_CONNECTIONS {
            return;
        }

        if let Some(addr) = self
            .peer_table
            .get_best_address(self.pending_addresses())
            .await
        {
            info!("[initiator] spinning up feeler connection to {}", addr);
            self.pending_attempts
                .lock()
                .unwrap()
                .insert(addr, ConnectionType::Feeler);

            let p2p = self.p2p.clone();
            let pending_tracker = self.pending_attempts.clone();
            tokio::spawn(async move {
                let result = p2p.connect_addr(addr, ConnectionType::Feeler).await;
                pending_tracker.lock().unwrap().remove(&addr);

                match result {
                    Ok(handle) => {
                        info!("[initiator] feeler handshake succeeded with {}", addr);
                        let _ = handle.disconnect().await;
                    }
                    Err(error) => {
                        debug!(
                            "[initiator] feeler connection to {} failed: {}",
                            addr, error
                        );
                    }
                }
            });
        }
    }

    async fn fill_connections(&self) {
        self.fill_type(
            ConnectionType::BlockRelayOnly,
            MAX_BLOCK_RELAY_ONLY_CONNECTIONS,
        )
        .await;
        self.fill_type(
            ConnectionType::OutboundFullRelay,
            MAX_OUTBOUND_FULL_RELAY_CONNECTIONS,
        )
        .await;
    }

    async fn fill_type(&self, conn_type: ConnectionType, target: usize) {
        let active = self.peer_table.get_peer_count_by_type(conn_type).await;
        let pending = self.pending_count(conn_type);
        let needed = connection_deficit(active, pending, target);

        debug!(
            "[initiator] type: {}, active: {}, pending: {}, target: {}, needed: {}",
            conn_type, active, pending, target, needed
        );

        for _ in 0..needed {
            let Some(addr) = self
                .peer_table
                .get_best_address(self.pending_addresses())
                .await
            else {
                break;
            };

            self.pending_attempts
                .lock()
                .unwrap()
                .insert(addr, conn_type);
            let p2p = self.p2p.clone();
            let pending_tracker = self.pending_attempts.clone();

            tokio::spawn(async move {
                let result = p2p.connect_addr(addr, conn_type).await;
                pending_tracker.lock().unwrap().remove(&addr);

                if let Err(error) = result {
                    debug!(
                        "[initiator] failed to connect to {} as {}: {}",
                        addr, conn_type, error
                    );
                } else {
                    info!("[initiator] connected to {} as {}", addr, conn_type);
                }
            });
        }
    }

    fn pending_count(&self, conn_type: ConnectionType) -> usize {
        self.pending_attempts
            .lock()
            .unwrap()
            .values()
            .filter(|pending_type| **pending_type == conn_type)
            .count()
    }

    fn pending_addresses(&self) -> Vec<SocketAddr> {
        self.pending_attempts
            .lock()
            .unwrap()
            .keys()
            .copied()
            .collect()
    }
}

fn connection_deficit(active: usize, pending: usize, target: usize) -> usize {
    target.saturating_sub(active.saturating_add(pending))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_deficit_counts_pending_attempts_against_quota() {
        assert_eq!(connection_deficit(5, 2, 8), 1);
        assert_eq!(connection_deficit(8, 0, 8), 0);
        assert_eq!(connection_deficit(8, 3, 8), 0);
    }

    #[test]
    fn bitcoin_core_outbound_classes_have_independent_deficits() {
        let full_relay_needed = connection_deficit(8, 0, MAX_OUTBOUND_FULL_RELAY_CONNECTIONS);
        let block_relay_needed = connection_deficit(0, 0, MAX_BLOCK_RELAY_ONLY_CONNECTIONS);

        assert_eq!(full_relay_needed, 0);
        assert_eq!(block_relay_needed, 2);
    }
}
