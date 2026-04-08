//! Bitcoin P2P network lifecycle.
//!
//! Starts the network, maintains peer connections, handles peer rotation.
//!
//! Bitcoin Core: CConnman in src/net.cpp — ThreadMessageHandler,
//! ThreadOpenConnections, ThreadDNSAddressSeed

use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::p2p::{
    actor::Actor, addr_man::AddrMan, dispatcher::DispatcherActor, errors::P2pError, message::Magic,
    peer_manager::PeerManager, peer_table::PeerTable, sync::SyncManager,
};

/// Target number of simultaneous peer connections.
const TARGET_OUTBOUND: usize = 8;
const MAX_INBOUND: usize = 117;

/// How long to wait between peer health checks.
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// Network configuration.
pub struct NetworkConfig {
    pub magic: Magic,
    pub port: u16,
}

impl NetworkConfig {
    pub fn signet() -> Self {
        Self {
            magic: Magic::Signet,
            port: 38333,
        }
    }

    pub fn mainnet() -> Self {
        Self {
            magic: Magic::Mainnet,
            port: 8333,
        }
    }
}

/// Start the Bitcoin P2P network services.
pub async fn run_p2p_maintenance(
    manager: std::sync::Arc<PeerManager>,
    config: NetworkConfig,
) -> Result<(), P2pError> {
    use crate::p2p::discovery::DiscoveryActor;
    use crate::p2p::initiator::ConnectionInitiator;

    info!(
        "[net] starting modern actor-based maintenance for network {:?}",
        config.magic
    );

    // 1. Start Discovery Actor (DNS seeding and periodic harvesting)
    let _discovery = DiscoveryActor::new(config.magic, config.port, manager.table.clone()).spawn();

    // 2. Start Connection Initiator (proactive outbound management)
    let _initiator =
        ConnectionInitiator::new(manager.table.clone(), manager.clone(), TARGET_OUTBOUND).spawn();

    // 3. Start Inbound Accept Loop
    let accept_manager = std::sync::Arc::clone(&manager);
    tokio::spawn(async move {
        accept_loop(accept_manager, config.port).await;
    });

    // 4. Maintenance Loop (Wait forever or handle shutdown)
    loop {
        sleep(HEALTH_CHECK_INTERVAL).await;
        let count = manager.table.get_peer_count().await.unwrap_or(0);
        debug!("[net] background check: {} active peers", count);
    }
}

/// Start the network with the full actor-system initialized.
pub async fn start_network(
    config: NetworkConfig,
    store: bitcrab_storage::Store,
) -> Result<(), P2pError> {
    let table = PeerTable::new(AddrMan::new());

    // Initialize Coordination Layers
    let sync = SyncManager::new(store.clone(), table.clone(), None);
    let dispatcher = DispatcherActor::new(table.clone(), sync).spawn();

    // Initialize Peer Manager with Dispatcher reference
    let manager = std::sync::Arc::new(PeerManager::new(config.magic, table, dispatcher));

    run_p2p_maintenance(manager, config).await
}

async fn accept_loop(manager: std::sync::Arc<PeerManager>, port: u16) {
    let listener = match tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await {
        Ok(l) => l,
        Err(e) => {
            warn!("Failed to bind to inbound port {}: {}", port, e);
            return;
        }
    };
    info!("Listening for inbound connections on 0.0.0.0:{}", port);

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let count = manager.table.get_peer_count().await.unwrap_or(0);
                if count >= TARGET_OUTBOUND + MAX_INBOUND {
                    debug!("Rejected inbound from {} (max peers reached)", addr);
                    continue;
                }
                if manager.is_banned(&addr.ip()) {
                    warn!("Rejected inbound from BANNED IP {}", addr.ip());
                    continue;
                }

                info!("Accepted inbound connection from {}", addr);
                let mg = std::sync::Arc::clone(&manager);

                tokio::spawn(async move {
                    if let Err(e) = mg.handshake(stream, addr, true).await {
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
