//! Bitcoin P2P network lifecycle.
//!
//! Starts the network, maintains peer connections, handles peer rotation.
//!
//! Bitcoin Core: CConnman in src/net.cpp — ThreadMessageHandler,
//! ThreadOpenConnections, ThreadDNSAddressSeed

use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn, debug};

use crate::p2p::{
    errors::P2pError,
    message::Magic,
    peer_manager::PeerManager,
    peer_table::PeerTable,
    addr_man::AddrMan,
    messages::Message,
};


/// Signet DNS seeds.
///
/// Bitcoin Core: src/kernel/chainparams.cpp vSeeds for signet
const SIGNET_DNS_SEEDS: &[&str] = &[
    "seed.signet.bitcoin.sprovoost.nl",
    "seed.signet.achow101.com",
];

/// Mainnet DNS seeds.
///
/// Bitcoin Core: src/kernel/chainparams.cpp vSeeds for mainnet
const MAINNET_DNS_SEEDS: &[&str] = &[
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "dnsseed.bitcoin.dashjr-list.of.hetzner.de",
    "seed.bitcoinstats.com",
    "seed.bitcoin.jonasschnelli.ch",
    "seed.btc.petertodd.net",
];

/// Target number of simultaneous peer connections.
///
/// Bitcoin Core: DEFAULT_MAX_PEER_CONNECTIONS = 125 in src/net.h
/// We start small.
const TARGET_OUTBOUND: usize = 8;
const MAX_INBOUND: usize = 117;

/// How long to wait between connection attempts.
#[allow(dead_code)]
const CONNECT_INTERVAL: Duration = Duration::from_secs(5);

/// How long to wait between peer health checks.
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// Network configuration.
pub struct NetworkConfig {
    pub magic:    Magic,
    pub port:     u16,
}

impl NetworkConfig {
    pub fn signet() -> Self {
        Self { magic: Magic::Signet, port: 38333 }
    }

    pub fn mainnet() -> Self {
        Self { magic: Magic::Mainnet, port: 8333 }
    }
}

/// Start the Bitcoin P2P network services.
///
/// This involves:
/// 1. DNS Seeding
/// 2. Listening for inbound connections
/// 3. Maintaining outbound connections
pub async fn run_p2p_maintenance(
    manager: std::sync::Arc<PeerManager>,
    config: NetworkConfig,
) -> Result<(), P2pError> {
    // 1. Initial DNS Seeding
    let seeds = match config.magic {
        Magic::Signet  => SIGNET_DNS_SEEDS,
        Magic::Mainnet => MAINNET_DNS_SEEDS,
        _              => SIGNET_DNS_SEEDS,
    };

    info!("[net] seeding from DNS for network {:?}", config.magic);
    manager.seed_from_dns(seeds, config.port).await;

    // 2. Start Accept Loop
    let accept_manager = std::sync::Arc::clone(&manager);
    tokio::spawn(async move {
        accept_loop(accept_manager, config.port).await;
    });

    // 3. Initial Outbound Connections
    fill_connections(&manager, TARGET_OUTBOUND).await;

    // 4. Maintenance Loop
    loop {
        sleep(HEALTH_CHECK_INTERVAL).await;

        let count = manager.table.get_peer_count().await.unwrap_or(0);
        debug!("[net] active peers: {} (target: {})", count, TARGET_OUTBOUND);

        // Refill outbound connections if below target.
        if count < TARGET_OUTBOUND {
            fill_connections(&manager, TARGET_OUTBOUND - count).await;
        }

        // Periodic Re-seeding if extremely low on addresses.
        let low_addresses = {
            let am = manager.addr_man.lock().unwrap();
            am.connectable_count() < TARGET_OUTBOUND * 2
        };

        if low_addresses {
            debug!("[net] address book low, re-seeding...");
            manager.seed_from_dns(seeds, config.port).await;
        }
    }
}

/// Legacy start_network for backward compatibility (optional, but refactored to use new logic).
pub async fn start_network(config: NetworkConfig) -> Result<(), P2pError> {
    let table = PeerTable::new(AddrMan::new());
    let manager = std::sync::Arc::new(PeerManager::new(config.magic, table));
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
                let count = manager.peer_count();
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
                    match mg.handshake(stream, addr, true).await {
                        Ok((_peer, mut incoming_rx)) => {
                            info!("Inbound handshake complete: {}", addr);
                            mg.insert_peer(addr);

                            // Process messages
                            loop {
                                match incoming_rx.recv().await {
                                    Some(Message::Addr(addr_msg)) => {
                                        let new_addrs: Vec<std::net::SocketAddr> = addr_msg.addresses.into_iter().map(|n| {
                                            std::net::SocketAddr::new(
                                                std::net::IpAddr::V6(std::net::Ipv6Addr::from(n.ip)),
                                                n.port
                                            )
                                        }).collect();
                                        mg.addr_man.lock().unwrap().add_many(new_addrs, addr);
                                    }

                                    // Ping is auto-handled by peer.rs reader task
                                    Some(other) => {
                                        debug!("[sync] ignoring message during header wait: {other:?}");
                                    }
                                    None => {
                                        warn!("Inbound connection to {} closed", addr);
                                        break;
                                    }
                                }
                            }
                        }

                        Err(e) => {
                            warn!("Inbound handshake with {} failed: {}", addr, e);
                        }
                    }
                });
            }
            Err(e) => {
                warn!("Accept failed: {}", e);
            }
        }
    }
}

/// Connect to peers until we reach the target count.
/// We spawn connection tasks and let them run independently.
async fn fill_connections(manager: &std::sync::Arc<PeerManager>, needed: usize) {
    println!("DEBUG: network::fill_connections BEGIN needed={}", needed);
    let mut attempts  = 0;
    let max_attempts  = needed * 5;
    let mut spawned = 0;

    while spawned < needed && attempts < max_attempts {
        println!("DEBUG: network::fill_connections loop attempt={}", attempts);
        attempts += 1;

        let active = Vec::new(); // TODO: get from PeerTable if needed

        let addr = {
            let am = manager.addr_man.lock().unwrap();
            am.select_best_ipv4(&active).or_else(|| am.select_best(&active))
        };


        let Some(addr) = addr else {
            debug!("no connectable peers in table");
            break;
        };

        // Mark this address as "attempted" so it isn't picked immediately again in the same loop
        // We do this by temporarily recording success or failure, but for now we just spawn it.
        manager.addr_man.lock().unwrap().record_success(addr); // Temporarily bump score to prevent duplicate selection

        let mg = std::sync::Arc::clone(manager);
        tokio::spawn(async move {
            match mg.connect_a(addr).await {
                Ok((peer, mut incoming_rx)) => {
                    info!("TCP connected to {}", addr);
                    mg.insert_peer(addr);
                    
                    // Task 4: send GetAddr right after successful connection!
                    use crate::p2p::messages::addr::GetAddr;
                    if let Err(e) = peer.send(Message::GetAddr(GetAddr)).await {
                        warn!("failed to send getaddr to {}: {}", addr, e);
                    }

                    // Task 4: Continously listen to messages.
                    loop {
                        match incoming_rx.recv().await {
                            Some(Message::Addr(addr_msg)) => {
                                let new_addrs: Vec<std::net::SocketAddr> = addr_msg.addresses.into_iter().map(|n| {
                                    std::net::SocketAddr::new(
                                        std::net::IpAddr::V6(std::net::Ipv6Addr::from(n.ip)),
                                        n.port
                                    )
                                }).collect();
                                debug!("Received {} addresses via gossip from {}", new_addrs.len(), addr);
                                mg.addr_man.lock().unwrap().add_many(new_addrs, addr);
                            }

                            // Ping is auto-handled by peer.rs reader task
                            // Process other messages later (Inv, Block, Headers, etc.)
                            Some(_msg) => {}
                            None => {
                                warn!("Connection to {} closed", addr);
                                break;
                            }
                        }
                    }

                    // Exit loop on disconnect.
                }
                Err(P2pError::SelfConnection) => {
                    debug!("self-connection detected, skipping {}", addr);
                }
                Err(e) => {
                    debug!("connection to {} failed: {}", addr, e);
                    mg.addr_man.lock().unwrap().record_failure(addr);
                }
            }
        });


        spawned += 1;
        // Don't sleep massively, let them spawn concurrently
        sleep(Duration::from_millis(100)).await;
    }

    if spawned > 0 {
        info!("spawned {} connection attempts", spawned);
    }
}