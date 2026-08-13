//! DiscoveryActor: Handles DNS seeding and periodic address harvesting.

use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, info};

use super::peer_table::PeerTable;

pub struct PeerDiscovery {
    network_id: String,
    port: u16,
    seeds: Vec<String>,
    peer_table: PeerTable,
}

impl PeerDiscovery {
    pub fn spawn(self) {
        let arc_self = std::sync::Arc::new(self);
        info!(
            "[discovery] starting discovery background task for {}",
            arc_self.network_id
        );

        // Initial seed
        let s = arc_self.clone();
        tokio::spawn(async move {
            s.seed_from_dns().await;
        });

        // Periodic maintenance
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(120));
            loop {
                interval.tick().await;
                let count = arc_self.peer_table.get_peer_count().await;
                if count < 100 {
                    arc_self.seed_from_dns().await;
                }
            }
        });
    }

    pub fn new(network_id: String, port: u16, seeds: Vec<String>, peer_table: PeerTable) -> Self {
        Self {
            network_id,
            port,
            seeds,
            peer_table,
        }
    }

    async fn seed_from_dns(&self) {
        use std::net::ToSocketAddrs;
        info!("[discovery] seeding from DNS for {}", self.network_id);

        for seed in &self.seeds {
            let host = format!("{}:{}", seed, self.port);
            match tokio::task::spawn_blocking(move || {
                host.to_socket_addrs().map(|i| i.collect::<Vec<_>>())
            })
            .await
            {
                Ok(Ok(addrs)) => {
                    let count = addrs.len();
                    let net_addrs = addrs
                        .into_iter()
                        .map(crate::p2p::messages::addr::NetAddr::from_socket_addr)
                        .collect();

                    let _ = self
                        .peer_table
                        .add_addresses(net_addrs, "0.0.0.0:0".parse().unwrap())
                        .await;
                    debug!("[discovery] DNS seed {} → {} addresses", seed, count);
                }
                _ => debug!("[discovery] DNS seed {} failed", seed),
            }
        }
    }
}
