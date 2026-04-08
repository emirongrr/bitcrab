//! Manages multiple Bitcoin P2P peer connections.
//!
//! Responsible for:
//! - Connecting to peers and completing the handshake
//! - Maintaining the active peer list
//! - Disconnecting dead or timed-out peers
//! - Providing access to peers for protocol operations
//!
//! Bitcoin Core: CConnman in src/net.h
//!
//! This is a simplified single-threaded version.
//! Full concurrent peer management comes later.
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tracing::{debug, info, warn};
use std::collections::HashSet;
use crate::p2p::addr_man::AddrMan;
use std::sync::{Arc, Mutex};
use std::path::PathBuf;
use tokio::sync::mpsc::Receiver;
use crate::p2p::messages::Message;

use crate::p2p::{
    codec::{decode_header, encode_header, verify_checksum},
    errors::P2pError,
    message::Magic,
    messages::{BitcoinMessage, version::Version, verack::Verack},
    peer::{PeerHandle, PeerInfo},
    peer_table::PeerTable,
};

use bitcrab_common::constants::MIN_PEER_PROTO_VERSION;



/// Connection timeout in seconds.
const CONNECT_TIMEOUT_SECS: u64 = 10;

/// Handshake timeout in seconds.
const HANDSHAKE_TIMEOUT_SECS: u64 = 30;

/// Manages a set of active peer connections.
///
/// Bitcoin Core: CConnman in src/net.h
pub struct PeerManager {
    pub table:  PeerTable,
    magic:      Magic,
    pub addr_man: Arc<Mutex<AddrMan>>,
    our_nonces: Arc<Mutex<HashSet<u64>>>,
    data_dir:   Option<PathBuf>,
    pub ban_list: Arc<Mutex<std::collections::HashMap<std::net::IpAddr, tokio::time::Instant>>>,
}



impl PeerManager {
    pub fn new(magic: Magic, table: PeerTable) -> Self {
        Self {
            table,
            magic,
            addr_man:   Arc::new(Mutex::new(AddrMan::new())),
            our_nonces: Arc::new(Mutex::new(HashSet::new())),
            data_dir:   None,
            ban_list:   Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }


    /// Ban an IP Address for a specific duration.
    pub fn ban(&self, ip: std::net::IpAddr, duration: tokio::time::Duration) {
        self.ban_list.lock().unwrap().insert(ip, tokio::time::Instant::now() + duration);
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

    pub fn insert_peer(&self, _addr: SocketAddr) {
        // Obsolete: PeerActor now notifies PeerTable automatically.
    }
    
    pub fn remove_peer(&self, _addr: &SocketAddr) {
        // Obsolete: PeerActor now notifies PeerTable automatically.
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
        }}


    /// Seed the peer table from DNS.
    ///
    /// Bitcoin Core: CConnman::ThreadDNSAddressSeed() in src/net.cpp
    pub async fn seed_from_dns(&self, seeds: &[&str], port: u16) {
        use std::net::ToSocketAddrs;
        for seed in seeds {
            let host = format!("{}:{}", seed, port);
            match tokio::task::spawn_blocking(move || {
                host.to_socket_addrs().map(|i| i.collect::<Vec<_>>())
            }).await {
                Ok(Ok(addrs)) => {
                    let count = addrs.len();
                    self.addr_man.lock().unwrap().add_many(addrs, "0.0.0.0:0".parse().unwrap());
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
    pub async fn connect(&self, addr: &str) -> Result<(PeerHandle, Receiver<Message>), P2pError> {
        let socket_addr = resolve(addr)?;
        self.connect_addr(socket_addr).await
    }

    pub async fn connect_a(&self, addr: SocketAddr) -> Result<(PeerHandle, Receiver<Message>), P2pError> {
        self.connect_addr(addr).await
    }

    pub async fn connect_best(&self) -> Result<(PeerHandle, Receiver<Message>), P2pError> {
        let addr = self.addr_man.lock().unwrap()
            .select_best(&[]) // TODO: provide active list from PeerTable
            .ok_or(P2pError::ConnectionFailed {
                addr: "none".into(),
                reason: "no connectable peers in table".into(),
            })?;
        self.connect_addr(addr).await
    }


    pub async fn connect_addr(&self, socket_addr: SocketAddr) -> Result<(PeerHandle, Receiver<Message>), P2pError> {
        if self.is_banned(&socket_addr.ip()) {
            return Err(P2pError::Banned);
        }
        
        info!("connecting to {}", socket_addr);

        let stream = timeout(
            Duration::from_secs(CONNECT_TIMEOUT_SECS),
            TcpStream::connect(socket_addr),
        )
        .await
        .map_err(|_| P2pError::HandshakeTimeout { secs: CONNECT_TIMEOUT_SECS })?
        .map_err(|e| P2pError::ConnectionFailed {
            addr: socket_addr.to_string(),
            reason: e.to_string(),
        })?;

        info!("TCP connected to {}", socket_addr);

        match self.handshake(stream, socket_addr, false).await {
            Ok(res) => {
                self.addr_man.lock().unwrap().record_success(socket_addr);
                self.table.add_peer(res.0.clone()).await.map_err(|_| P2pError::ConnectionClosed)?;
                self.save_peers(); 
                Ok(res)
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
    /// ProcessMessage() handlers for "version" and "verack".

    pub async fn handshake(
    &self,
    mut stream: TcpStream,
    addr: SocketAddr,
    is_inbound: bool,
) -> Result<(PeerHandle, Receiver<Message>), P2pError> {

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let nonce = make_nonce();
    self.our_nonces.lock().unwrap().insert(nonce);

    let our_version = Version::our_version_with_nonce(nonce);
    let payload     = our_version.encode();
    let header      = encode_header(self.magic, &Version::COMMAND, &payload);
    
    if !is_inbound {
        stream.write_all(&header).await?;
        stream.write_all(&payload).await?;
        debug!("[{}] sent version nonce={}", addr, nonce);
    }

    let mut peer_version  = 0i32;
    let mut peer_agent    = String::new();
    let mut peer_height   = 0i32;
    let mut peer_services = 0u64;
    let mut got_version   = false;
    let mut got_verack    = false;

    // Copy nonces to avoid borrow conflict in async block if not using shared reference directly.
    let our_nonces_snapshot: std::collections::HashSet<u64> = self.our_nonces.lock().unwrap().clone();
    let magic = self.magic;

    let result = timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), async {
        loop {
            let mut hdr_buf = [0u8; 24];
            stream.read_exact(&mut hdr_buf).await
                .map_err(|_| P2pError::ConnectionClosed)?;

            let msg_hdr = decode_header(&hdr_buf, magic)?;
            debug!("[{}] received {:?}", addr, msg_hdr.command);

            let mut payload_buf = vec![0u8; msg_hdr.length as usize];
            if msg_hdr.length > 0 {
                stream.read_exact(&mut payload_buf).await
                    .map_err(|_| P2pError::ConnectionClosed)?;
            }

            verify_checksum(&msg_hdr, &payload_buf)?;

            match Message::decode(&msg_hdr.command, &payload_buf)
                .map_err(|e| P2pError::DecodeError(e.to_string()))?
            {
                Message::Version(v) => {
                    // Self-connection detection.
                    // Bitcoin Core: nonce check in src/net.cpp
                    if our_nonces_snapshot.contains(&v.nonce) {
                        return Err(P2pError::SelfConnection);
                    }

                    if v.version < MIN_PEER_PROTO_VERSION as i32 {
                        return Err(P2pError::PeerVersionTooOld {
                            version: v.version,
                            minimum: MIN_PEER_PROTO_VERSION as i32,
                        });
                    }

                    peer_version  = v.version;
                    peer_agent    = v.user_agent.clone();
                    peer_height   = v.start_height;
                    peer_services = v.services;

                    info!(
                        "[{}] peer version={} agent='{}' height={}",
                        addr, peer_version, peer_agent, peer_height
                    );

                    if is_inbound {
                        // Send our version back
                        stream.write_all(&header).await?;
                        stream.write_all(&payload).await?;
                        debug!("[{}] sent version nonce={} (inbound reply)", addr, nonce);
                    }

                    let verack_payload = Verack.encode();
                    let verack_header  = encode_header(magic, &Verack::COMMAND, &verack_payload);
                    stream.write_all(&verack_header).await?;
                    debug!("[{}] sent verack", addr);
                    got_version = true;
                }

                Message::Verack(_) => { got_verack = true; }

                other => { debug!("[{}] ignoring {} during handshake", addr, other); }
            }

            if got_version && got_verack {
                return Ok(());
            }
        }
    })
    .await
    .map_err(|_| P2pError::HandshakeTimeout { secs: HANDSHAKE_TIMEOUT_SECS })?;

    self.our_nonces.lock().unwrap().remove(&nonce);
    result?;

    info!("[{}] handshake complete", addr);

    let (handle, rx) = PeerHandle::start(
        addr, 
        self.magic, 
        stream, 
        peer_version, 
        peer_agent, 
        peer_height, 
        peer_services,
        Arc::clone(&self.ban_list),
        self.table.clone()
    );

    if !is_inbound {
        debug!("[{}] requesting peers (getaddr) after handshake", addr);
        let _ = handle.send(Message::GetAddr(crate::p2p::messages::addr::GetAddr)).await;
    }

    Ok((handle, rx))

}

    pub fn peer_count(&self) -> usize {
        // Handled via actor call now. Returning 0 or similar if non-async access needed,
        // but better to move caller to async.
        0
    }
    
    pub fn active_addrs(&self) -> Vec<SocketAddr> {
        Vec::new()
    }

    pub fn prune_disconnected(&self) {
        // Obsolete.
    }

    pub fn disconnect_all(&self) {
        // TODO: trigger via PeerTable.
    }
}


fn resolve(addr: &str) -> Result<SocketAddr, P2pError> {
    addr.parse().or_else(|_| {
        use std::net::ToSocketAddrs;
        addr.to_socket_addrs()
            .map_err(|e| P2pError::ConnectionFailed {
                addr: addr.to_string(),
                reason: e.to_string(),
            })?
            .next()
            .ok_or(P2pError::ConnectionFailed {
                addr: addr.to_string(),
                reason: "DNS resolution returned no addresses".into(),
            })
    })
}

/// Cryptographically random nonce for self-connection detection.
///
/// Bitcoin Core: GetRand(std::numeric_limits<uint64_t>::max()) in src/net.cpp
fn make_nonce() -> u64 {
    rand::random()
}
