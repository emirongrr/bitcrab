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

/// Start the Bitcoin P2P network.
///
/// Seeds from DNS, connects to peers, and runs the peer maintenance loop.
/// This function runs indefinitely.
///
/// Bitcoin Core: AppInitMain() → CConnman::Start() in src/net.cpp
pub async fn start_network(config: NetworkConfig) -> Result<(), P2pError> {
    println!("DEBUG: network::start_network BEGIN");
    // Load peer table from disk if available.
    // Bitcoin Core: CAddrMan loaded from peers.dat in AppInitMain()
    let data_dir = std::path::PathBuf::from(".");
    let manager = std::sync::Arc::new(PeerManager::new(config.magic)
        .with_data_dir(data_dir));

    let known_count = manager.table.lock().unwrap().len();
    if known_count > 0 {
        info!("loaded {} known peers from disk", known_count);
    }

    // Seed from DNS — adds new addresses to the table.
    let seeds = match config.magic {
        Magic::Signet  => SIGNET_DNS_SEEDS,
        Magic::Mainnet => MAINNET_DNS_SEEDS,
        _              => SIGNET_DNS_SEEDS,
    };

    println!("DEBUG: network::start_network about to seed DNS");
    manager.seed_from_dns(seeds, config.port).await;
    println!("DEBUG: network::start_network DNS seed finished");
    println!("DEBUG: about to lock table for count");
    let count = {
        let table = manager.table.lock().unwrap();
        println!("DEBUG: table lock acquired for count");
        let len = table.len();
        let conn = table.connectable_count();
        (len, conn)
    };
    println!("DEBUG: table lock released, count: {}/{}", count.0, count.1);
    
    // Start listening for inbound connections.
    println!("DEBUG: starting accept_loop");
    let accept_manager = std::sync::Arc::clone(&manager);
    tokio::spawn(async move {
        accept_loop(accept_manager, config.port).await;
    });

    // Initial connections.
    println!("DEBUG: network::start_network about to fill_connections");
    fill_connections(&manager, TARGET_OUTBOUND).await;
    println!("DEBUG: network::start_network fill_connections spawned");

    // Main loop: maintain connections, check health.
    //
    // Bitcoin Core: CConnman::ThreadOpenConnections() in src/net.cpp
    loop {
        sleep(HEALTH_CHECK_INTERVAL).await;

        // Remove dead peers.
        manager.prune_disconnected();

        let count = manager.peer_count();
        info!("active peers: {} (outbound limit: {}, inbound limit: {})", count, TARGET_OUTBOUND, MAX_INBOUND);

        // Refill if below target.
        if count < TARGET_OUTBOUND {
            fill_connections(&manager, TARGET_OUTBOUND - count).await;
        }

        // Re-seed if table is running low.
        if manager.table.lock().unwrap().connectable_count() < TARGET_OUTBOUND * 2 {
            manager.seed_from_dns(seeds, config.port).await;
        }
    }
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
                                    Some(crate::p2p::messages::Message::Addr(addr_msg)) => {
                                        let new_addrs: Vec<std::net::SocketAddr> = addr_msg.addresses.into_iter().map(|n| {
                                            std::net::SocketAddr::new(
                                                std::net::IpAddr::V6(std::net::Ipv6Addr::from(n.ip)),
                                                n.port
                                            )
                                        }).collect();
                                        mg.table.lock().unwrap().add_many(new_addrs, addr);
                                    }
                                    // Ping is auto-handled by peer.rs reader task
                                    Some(_msg) => {
                                        // Forward block/inv messages to SyncManager here later
                                    }
                                    None => {
                                        warn!("Inbound connection to {} closed", addr);
                                        break;
                                    }
                                }
                            }
                            mg.remove_peer(&addr);
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

        let active = manager.active_addrs();

        let addr = {
            let guard = manager.table.lock().unwrap();
            guard.select_best_ipv4(&active).or_else(|| guard.select_best(&active))
        };

        let Some(addr) = addr else {
            debug!("no connectable peers in table");
            break;
        };

        // Mark this address as "attempted" so it isn't picked immediately again in the same loop
        // We do this by temporarily recording success or failure, but for now we just spawn it.
        manager.table.lock().unwrap().record_success(addr); // Temporarily bump score to prevent duplicate selection

        let mg = std::sync::Arc::clone(manager);
        tokio::spawn(async move {
            match mg.connect_a(addr).await {
                Ok((peer, mut incoming_rx)) => {
                    info!("TCP connected to {}", addr);
                    mg.insert_peer(addr);
                    
                    // Task 4: send GetAddr right after successful connection!
                    use crate::p2p::messages::addr::GetAddr;
                    if let Err(e) = peer.send(&GetAddr) {
                        warn!("failed to send getaddr to {}: {}", addr, e);
                    }

                    // Task 4: Continously listen to messages.
                    loop {
                        match incoming_rx.recv().await {
                            Some(crate::p2p::messages::Message::Addr(addr_msg)) => {
                                let new_addrs: Vec<std::net::SocketAddr> = addr_msg.addresses.into_iter().map(|n| {
                                    std::net::SocketAddr::new(
                                        std::net::IpAddr::V6(std::net::Ipv6Addr::from(n.ip)),
                                        n.port
                                    )
                                }).collect();
                                info!("Received {} addresses via gossip from {}", new_addrs.len(), addr);
                                mg.table.lock().unwrap().add_many(new_addrs, addr);
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

                    mg.remove_peer(&addr);
                }
                Err(P2pError::SelfConnection) => {
                    debug!("self-connection detected, skipping {}", addr);
                }
                Err(e) => {
                    debug!("connection to {} failed: {}", addr, e);
                    // Undo the temporary bump since it failed
                    mg.table.lock().unwrap().record_failure(addr);
                    mg.table.lock().unwrap().record_failure(addr);
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