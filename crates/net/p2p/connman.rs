use crate::p2p::addr_man::AddrMan;
use crate::p2p::messages::Message;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tracing::{debug, info, warn};

use crate::p2p::{
    codec::{decode_header, encode_header, verify_checksum},
    errors::P2pError,
    message::Magic,
    messages::{verack::Verack, version::Version, BitcoinMessage},
    net_types::ConnectionType,
    node::{Node, NodeHandle},
    peer_manager::PeerManager,
    peer_table::PeerTable,
};

use bitcrab_common::constants::MIN_PEER_PROTO_VERSION;

/// Connection timeout in seconds.
const CONNECT_TIMEOUT_SECS: u64 = 10;

/// Handshake timeout in seconds.
const HANDSHAKE_TIMEOUT_SECS: u64 = 30;

/// High-level P2P network service managing peer connections.
///
/// Bitcoin Core: CConnman in src/net.h
pub struct Connman {
    pub peer_table: PeerTable,
    pub magic: Magic,
    pub peer_manager: Arc<PeerManager>,
    pub addr_man: Arc<Mutex<AddrMan>>,
    our_nonces: Arc<Mutex<HashSet<u64>>>,
    data_dir: Option<PathBuf>,
    pub ban_list: Arc<Mutex<std::collections::HashMap<std::net::IpAddr, tokio::time::Instant>>>,
}

impl Connman {
    pub fn new(magic: Magic, peer_table: PeerTable, peer_manager: Arc<PeerManager>) -> Self {
        Self {
            peer_table,
            magic,
            peer_manager,
            addr_man: Arc::new(Mutex::new(AddrMan::new())),
            our_nonces: Arc::new(Mutex::new(HashSet::new())),
            data_dir: None,
            ban_list: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Ban an IP Address for a specific duration.
    pub fn ban(&self, ip: std::net::IpAddr, duration: tokio::time::Duration) {
        self.ban_list
            .lock()
            .unwrap()
            .insert(ip, tokio::time::Instant::now() + duration);
        info!("Banned IP {} for {:?}", ip, duration);
    }

    /// Check if an IP address is currently banned.
    pub fn is_banned(&self, ip: &std::net::IpAddr) -> bool {
        let mut map = self.ban_list.lock().unwrap();
        if let Some(until) = map.get(ip) {
            if until > &tokio::time::Instant::now() {
                return true;
            } else {
                map.remove(ip);
            }
        }
        false
    }

    pub fn with_data_dir(mut self, dir: PathBuf) -> Self {
        let peers_file = dir.join("peers.dat");
        self.addr_man = Arc::new(Mutex::new(AddrMan::load_or_default(&peers_file)));
        self.data_dir = Some(dir);
        self
    }

    /// Save peer table to disk.
    pub fn save_peers(&self) {
        if let Some(ref dir) = self.data_dir {
            let path = dir.join("peers.dat");
            if let Err(e) = self.addr_man.lock().unwrap().save(&path) {
                warn!("failed to save peer table: {}", e);
            }
        }
    }

    /// Seed the peer table from DNS.
    ///
    /// Bitcoin Core: CConnman::ThreadDNSAddressSeed() in src/net.cpp
    pub async fn seed_from_dns(&self, seeds: &[&str], port: u16) {
        use std::net::ToSocketAddrs;
        for seed in seeds {
            let host = format!("{}:{}", seed, port);
            match tokio::task::spawn_blocking(move || {
                host.to_socket_addrs().map(|i| i.collect::<Vec<_>>())
            })
            .await
            {
                Ok(Ok(addrs)) => {
                    let count = addrs.len();
                    self.addr_man
                        .lock()
                        .unwrap()
                        .add_many(addrs, "0.0.0.0:0".parse().unwrap());
                    debug!("DNS seed {} → {} addresses", seed, count);
                }
                _ => debug!("DNS seed {} failed", seed),
            }
        }
    }

    /// Connect to a peer address and complete the Bitcoin handshake.
    ///
    /// On success the peer is added to the active peer list.
    ///
    /// Bitcoin Core: CConnman::OpenNetworkConnection() in src/net.cpp
    /// Connect to a specific address.
    pub async fn connect(
        &self,
        addr: &str,
        conn_type: ConnectionType,
    ) -> Result<NodeHandle, P2pError> {
        let socket_addr = resolve(addr)?;
        self.connect_addr(socket_addr, conn_type).await
    }

    pub async fn connect_addr(
        &self,
        mut socket_addr: SocketAddr,
        conn_type: ConnectionType,
    ) -> Result<NodeHandle, P2pError> {
        if let SocketAddr::V6(v6) = socket_addr {
            if let Some(v4) = v6.ip().to_ipv4_mapped() {
                socket_addr = SocketAddr::new(std::net::IpAddr::V4(v4), socket_addr.port());
                debug!("normalized address {} to {}", v6, socket_addr);
            }
        }

        if self.is_banned(&socket_addr.ip()) {
            return Err(P2pError::Banned);
        }

        info!("connecting to {}", socket_addr);

        let stream = timeout(
            Duration::from_secs(CONNECT_TIMEOUT_SECS),
            TcpStream::connect(socket_addr),
        )
        .await
        .map_err(|_| P2pError::HandshakeTimeout {
            secs: CONNECT_TIMEOUT_SECS,
        })?
        .map_err(|e| P2pError::ConnectionFailed {
            addr: socket_addr.to_string(),
            reason: e.to_string(),
        })?;

        info!("TCP connected to {} (type: {})", socket_addr, conn_type);

        match self.handshake(stream, socket_addr, false, conn_type).await {
            Ok(handle) => {
                self.addr_man.lock().unwrap().record_success(socket_addr);
                // Deprecated direct table add; PeerManager tracks connected nodes
                self.save_peers();
                Ok(handle)
            }
            Err(e) => {
                self.addr_man.lock().unwrap().record_failure(socket_addr);
                self.save_peers();
                Err(e)
            }
        }
    }

    /// Run the version/verack handshake on an established stream.
    ///
    /// Bitcoin Core: version/verack exchange in src/net_processing.cpp
    pub async fn handshake(
        &self,
        mut stream: TcpStream,
        addr: SocketAddr,
        is_inbound: bool,
        conn_type: ConnectionType,
    ) -> Result<NodeHandle, P2pError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let nonce = make_nonce();
        self.our_nonces.lock().unwrap().insert(nonce);

        // Fetch current height directly from SyncManager for the handshake
        let (_, height) = self.peer_manager.sync_manager.get_blocks_tip();
        let our_version = Version::our_version_with_nonce(
            nonce,
            height as i32,
            conn_type.is_tx_relay_connection(),
        );
        let payload = our_version.encode();
        let header = encode_header(self.magic, &Version::COMMAND, &payload);

        if !is_inbound {
            stream.write_all(&header).await?;
            stream.write_all(&payload).await?;
            debug!("[{}] sent version nonce={}", addr, nonce);
        }

        let mut peer_version = 0i32;
        let mut peer_agent = String::new();
        let mut peer_height = 0i32;
        let mut peer_services = 0u64;
        let mut got_version = false;
        let mut got_verack = false;

        let magic = self.magic;

        let result = timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), async {
            loop {
                let mut hdr_buf = [0u8; 24];
                stream
                    .read_exact(&mut hdr_buf)
                    .await
                    .map_err(|_| P2pError::ConnectionClosed)?;

                let msg_hdr = match decode_header(&hdr_buf, magic) {
                    Ok(hdr) => hdr,
                    Err(e) => {
                        return Err(e);
                    }
                };

                let mut payload_buf = vec![0u8; msg_hdr.length as usize];
                if msg_hdr.length > 0 {
                    stream
                        .read_exact(&mut payload_buf)
                        .await
                        .map_err(|_| P2pError::ConnectionClosed)?;
                }

                verify_checksum(&msg_hdr, &payload_buf)?;

                match Message::decode(&msg_hdr.command, &payload_buf)
                    .map_err(|e| P2pError::DecodeError(e.to_string()))?
                {
                    Message::Version(v) => {
                        if got_version {
                            return Err(P2pError::DuplicateHandshakeMessage { command: "version" });
                        }

                        if self.our_nonces.lock().unwrap().contains(&v.nonce) {
                            return Err(P2pError::SelfConnection);
                        }

                        if v.version < MIN_PEER_PROTO_VERSION as i32 {
                            return Err(P2pError::PeerVersionTooOld {
                                version: v.version,
                                minimum: MIN_PEER_PROTO_VERSION as i32,
                            });
                        }

                        peer_version = v.version;
                        peer_agent = v.user_agent.clone();
                        peer_height = v.start_height;
                        peer_services = v.services;

                        info!(
                            "[{}] peer version={} agent='{}' height={}",
                            addr, peer_version, peer_agent, peer_height
                        );

                        if is_inbound {
                            stream.write_all(&header).await?;
                            stream.write_all(&payload).await?;
                        }

                        let verack_payload = Verack.encode();
                        let verack_header = encode_header(magic, &Verack::COMMAND, &verack_payload);
                        stream.write_all(&verack_header).await?;
                        got_version = true;
                    }

                    Message::Verack(_) => {
                        if !got_version {
                            return Err(P2pError::DecodeError(
                                "received verack before version during handshake".into(),
                            ));
                        }
                        if got_verack {
                            return Err(P2pError::DuplicateHandshakeMessage { command: "verack" });
                        }
                        got_verack = true;
                    }

                    other => {
                        debug!("[{}] ignoring {} during handshake", addr, other);
                    }
                }

                if got_version && got_verack {
                    return Ok(());
                }
            }
        })
        .await;
        self.our_nonces.lock().unwrap().remove(&nonce);

        result.map_err(|_| P2pError::HandshakeTimeout {
            secs: HANDSHAKE_TIMEOUT_SECS,
        })??;

        info!("[{}] handshake complete", addr);

        let handle = Node::new(addr, self.magic, stream).start(
            peer_services,
            conn_type,
            self.peer_manager.clone(),
        );
        self.peer_table.add_peer(handle.clone()).await;
        self.peer_manager
            .initialize_node(addr, peer_height as u32, conn_type)
            .await;

        if !is_inbound {
            debug!("[{}] requesting peers (getaddr) after handshake", addr);
            let _ = handle
                .send(Message::GetAddr(crate::p2p::messages::addr::GetAddr))
                .await;
        }

        self.peer_manager.sync_with_peer(handle.clone()).await;
        self.peer_manager
            .sync_manager
            .update_peer_height(addr, peer_height as u32);

        Ok(handle)
    }
}

fn resolve(addr: &str) -> Result<SocketAddr, crate::p2p::errors::P2pError> {
    addr.parse().or_else(|_| {
        use std::net::ToSocketAddrs;
        addr.to_socket_addrs()
            .map_err(|e| crate::p2p::errors::P2pError::ConnectionFailed {
                addr: addr.to_string(),
                reason: e.to_string(),
            })?
            .next()
            .ok_or(crate::p2p::errors::P2pError::ConnectionFailed {
                addr: addr.to_string(),
                reason: "DNS resolution returned no addresses".into(),
            })
    })
}

fn make_nonce() -> u64 {
    rand::random()
}
