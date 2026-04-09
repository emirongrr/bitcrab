//! DiscoveryActor: Handles DNS seeding and periodic address harvesting.

use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, info};

use super::{
    actor::{Actor, ActorError, Context},
    message::Magic,
    peer_table::PeerTable,
};

/// Messages handled by the DiscoveryActor.
pub enum DiscoveryMessage {
    /// Perform an immediate DNS seed.
    SeedNow,
    /// Trigger periodic maintenance.
    Maintenance,
}

pub struct DiscoveryActor {
    magic: Magic,
    port: u16,
    seeds: Vec<String>,
    peer_table: PeerTable,
}

impl DiscoveryActor {
    pub fn new(magic: Magic, port: u16, peer_table: PeerTable) -> Self {
        let seeds = match magic {
            Magic::Mainnet => vec![
                "seed.bitcoin.sipa.be".to_string(),
                "dnsseed.bluematt.me".to_string(),
                "dnsseed.bitcoin.dashjr-list.of.hetzner.de".to_string(),
                "seed.bitcoinstats.com".to_string(),
                "seed.bitcoin.jonasschnelli.ch".to_string(),
                "seed.btc.petertodd.net".to_string(),
            ],
            Magic::Signet => vec![
                "seed.signet.bitcoin.sprovoost.nl".to_string(),
                "seed.signet.achow101.com".to_string(),
            ],
            _ => vec![],
        };

        Self {
            magic,
            port,
            seeds,
            peer_table,
        }
    }

    async fn seed_from_dns(&self) {
        use std::net::ToSocketAddrs;
        info!("[discovery] seeding from DNS for network {:?}", self.magic);

        for seed in &self.seeds {
            let host = format!("{}:{}", seed, self.port);
            match tokio::task::spawn_blocking(move || {
                host.to_socket_addrs().map(|i| i.collect::<Vec<_>>())
            })
            .await
            {
                Ok(Ok(addrs)) => {
                    let count = addrs.len();
                    // In a production Bitcoin node, we'd use a special NetAddr with services=0 for DNS seeds
                    let net_addrs = addrs
                        .into_iter()
                        .map(|a| crate::p2p::messages::addr::NetAddr::from_socket_addr(a))
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

impl Actor for DiscoveryActor {
    type Message = DiscoveryMessage;

    fn on_start(
        &mut self,
        ctx: &mut Context<Self>,
    ) -> impl std::future::Future<Output = Result<(), ActorError>> + Send {
        let handle = ctx.handle();
        async move {
            info!("[discovery] starting discovery actor");
            // Perform initial seed
            let _ = handle.cast(DiscoveryMessage::SeedNow).await;

            // Start periodic maintenance timer
            tokio::spawn(async move {
                let mut interval = interval(Duration::from_secs(120)); // Check every 2 minutes
                loop {
                    interval.tick().await;
                    let _ = handle.cast(DiscoveryMessage::Maintenance).await;
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
                DiscoveryMessage::SeedNow => {
                    self.seed_from_dns().await;
                }
                DiscoveryMessage::Maintenance => {
                    let count = self.peer_table.get_peer_count().await.unwrap_or(0);
                    if count < 100 { // If we have fewer than 100 known addresses
                        self.seed_from_dns().await;
                    }
                }
            }
            Ok(())
        }
    }
}
