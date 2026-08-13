//! Bitcoin P2P network lifecycle.
//!
//! Starts the network, maintains peer connections, handles peer rotation.
//!
//! Bitcoin Core: CConnman in src/net.cpp — ThreadMessageHandler,
//! ThreadOpenConnections, ThreadDNSAddressSeed

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::p2p::{
    connman::Connman,
    errors::P2pError,
    net_types::{ConnectionType, MAX_INBOUND_CONNECTIONS},
};

/// How long to wait between peer health checks.
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// Start the Bitcoin P2P network services.
pub async fn run_p2p_maintenance(
    p2p: std::sync::Arc<Connman>,
    chain: bitcrab_common::ChainType,
) -> Result<(), P2pError> {
    use crate::p2p::discovery::PeerDiscovery;
    use crate::p2p::initiator::ConnectionInitiator;

    let params = chain.chain_params();
    let _magic = params.magic;
    let port = params.default_port;
    let seeds = params.dns_seeds.iter().map(|s| s.to_string()).collect();

    info!(
        "[net] starting bitcrab network services for chain: {}",
        chain
    );

    // 1. Start Discovery (DNS seeding and periodic harvesting)
    PeerDiscovery::new(format!("{}", chain), port, seeds, p2p.peer_table.clone()).spawn();

    // 2. Start Connection Initiator (proactive outbound management)
    ConnectionInitiator::new(p2p.peer_table.clone(), p2p.clone()).spawn();

    // 3. Start Inbound Accept Loop
    let accept_p2p = std::sync::Arc::clone(&p2p);
    tokio::spawn(async move {
        accept_loop(accept_p2p, port).await;
    });

    // 4. Maintenance Loop (Wait forever or handle shutdown)
    loop {
        sleep(HEALTH_CHECK_INTERVAL).await;
        let counts = p2p.peer_table.get_connection_counts().await;
        debug!(
            "[net] peers: total={}, inbound={}, full-relay={}, block-relay-only={}, feeler={}",
            counts.total(),
            counts.inbound,
            counts.outbound_full_relay,
            counts.block_relay_only,
            counts.feeler
        );
    }
}

async fn accept_loop(p2p: std::sync::Arc<Connman>, port: u16) {
    let listener = match tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await {
        Ok(l) => l,
        Err(e) => {
            warn!("Failed to bind to inbound port {}: {}", port, e);
            return;
        }
    };
    info!("Listening for inbound connections on 0.0.0.0:{}", port);
    let pending_inbound = Arc::new(AtomicUsize::new(0));

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let active_inbound = p2p
                    .peer_table
                    .get_peer_count_by_type(ConnectionType::Inbound)
                    .await;
                let reserved = try_reserve_inbound_slot(
                    &pending_inbound,
                    active_inbound,
                    MAX_INBOUND_CONNECTIONS,
                );
                if !reserved {
                    debug!(
                        "Rejected inbound from {} ({} inbound slots full)",
                        addr, MAX_INBOUND_CONNECTIONS
                    );
                    continue;
                }
                if p2p.is_banned(&addr.ip()) {
                    pending_inbound.fetch_sub(1, Ordering::AcqRel);
                    warn!("Rejected inbound from BANNED IP {}", addr.ip());
                    continue;
                }

                info!("Accepted inbound connection from {}", addr);
                let p2p_handler = std::sync::Arc::clone(&p2p);
                let pending_inbound = pending_inbound.clone();

                tokio::spawn(async move {
                    let result = p2p_handler
                        .handshake(stream, addr, true, ConnectionType::Inbound)
                        .await;
                    pending_inbound.fetch_sub(1, Ordering::AcqRel);

                    if let Err(e) = result {
                        warn!("Inbound handshake with {} failed: {}", addr, e);
                    } else {
                        info!("Inbound handshake complete: {}", addr);
                    }
                });
            }
            Err(e) => {
                warn!("Accept failed: {}", e);
            }
        }
    }
}

fn try_reserve_inbound_slot(
    pending_inbound: &AtomicUsize,
    active_inbound: usize,
    max_inbound: usize,
) -> bool {
    pending_inbound
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
            (active_inbound.saturating_add(pending) < max_inbound).then_some(pending + 1)
        })
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inbound_reservations_never_exceed_available_slots() {
        let pending = AtomicUsize::new(0);
        let active = MAX_INBOUND_CONNECTIONS - 2;

        assert!(try_reserve_inbound_slot(
            &pending,
            active,
            MAX_INBOUND_CONNECTIONS
        ));
        assert!(try_reserve_inbound_slot(
            &pending,
            active,
            MAX_INBOUND_CONNECTIONS
        ));
        assert!(!try_reserve_inbound_slot(
            &pending,
            active,
            MAX_INBOUND_CONNECTIONS
        ));
        assert_eq!(pending.load(Ordering::Acquire), 2);
    }

    #[test]
    fn inbound_slot_can_be_reused_after_failed_handshake() {
        let pending = AtomicUsize::new(0);
        let active = MAX_INBOUND_CONNECTIONS - 1;

        assert!(try_reserve_inbound_slot(
            &pending,
            active,
            MAX_INBOUND_CONNECTIONS
        ));
        assert!(!try_reserve_inbound_slot(
            &pending,
            active,
            MAX_INBOUND_CONNECTIONS
        ));

        pending.fetch_sub(1, Ordering::AcqRel);

        assert!(try_reserve_inbound_slot(
            &pending,
            active,
            MAX_INBOUND_CONNECTIONS
        ));
    }

    #[test]
    fn full_inbound_table_rejects_before_handshake() {
        let pending = AtomicUsize::new(0);
        assert!(!try_reserve_inbound_slot(
            &pending,
            MAX_INBOUND_CONNECTIONS,
            MAX_INBOUND_CONNECTIONS
        ));
        assert_eq!(pending.load(Ordering::Acquire), 0);
    }
}
