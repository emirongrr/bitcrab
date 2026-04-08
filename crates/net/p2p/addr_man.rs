//! Bitcoin-style Address Manager (AddrMan) with Sybil-resistant bucketing.
//!
//! Replaces the simple PeerTable with CAddrMan-inspired buckets:
//! - New Table: 1024 buckets, filled from gossip/DNS.
//! - Tried Table: 64 buckets, filled only after successful handshakes.

use crate::p2p::messages::addr::NetAddr;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    hash::{Hash, Hasher},
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};
use std::{fs, path::Path};
use tracing::{debug, info};

const ADDRMAN_NEW_BUCKET_COUNT: usize = 1024;
const ADDRMAN_TRIED_BUCKET_COUNT: usize = 64;
const ADDRMAN_BUCKET_SIZE: usize = 64;

const MAX_SCORE: i32 = 100;
const MIN_SCORE: i32 = -10;
const BAN_DURATION: Duration = Duration::from_secs(60 * 10); // 10 min
const RETRY_INTERVAL: Duration = Duration::from_secs(60 * 2); // 2 min

/// Serializable snapshot for `peers.dat` persistence using bincode
#[derive(Serialize, Deserialize)]
struct AddrManSnapshot {
    key: [u8; 32],
    entries: Vec<PersistedAddrInfo>,
}

#[derive(Serialize, Deserialize)]
struct PersistedAddrInfo {
    addr: String,
    source: String,
    score: i32,
    is_tried: bool,
    success_count: u32,
    failure_count: u32,
}

#[derive(Debug, Clone)]
pub struct AddrInfo {
    pub addr: SocketAddr,
    pub source: SocketAddr, // who told us about this IP
    pub score: i32,
    pub is_tried: bool,
    pub last_connected: Option<Instant>,
    pub last_attempt: Option<Instant>,
    pub banned_at: Option<Instant>,
    pub success_count: u32,
    pub failure_count: u32,
}

impl AddrInfo {
    fn new(addr: SocketAddr, source: SocketAddr) -> Self {
        Self {
            addr,
            source,
            score: 0,
            is_tried: false,
            last_connected: None,
            last_attempt: None,
            banned_at: None,
            success_count: 0,
            failure_count: 0,
        }
    }

    pub fn is_banned(&self) -> bool {
        match self.banned_at {
            None => false,
            Some(t) => t.elapsed() < BAN_DURATION,
        }
    }

    pub fn is_too_recent(&self) -> bool {
        match self.last_attempt {
            None => false,
            Some(t) => t.elapsed() < RETRY_INTERVAL,
        }
    }

    pub fn is_connectable(&self) -> bool {
        !self.is_banned() && !self.is_too_recent()
    }

    pub fn to_net_addr(&self) -> NetAddr {
        let ip_bytes = match self.addr.ip() {
            IpAddr::V4(ipv4) => ipv4.to_ipv6_mapped().octets(),
            IpAddr::V6(ipv6) => ipv6.octets(),
        };

        NetAddr {
            time: self
                .last_connected
                .map(|t| t.elapsed().as_secs() as u32)
                .unwrap_or(0),
            services: 1, // Default to NODE_NETWORK, in production this should be stored or queried
            ip: ip_bytes,
            port: self.addr.port(),
        }
    }
}

pub struct AddrMan {
    pub map_info: HashMap<SocketAddr, AddrInfo>,
    new_buckets: Vec<Vec<SocketAddr>>,
    tried_buckets: Vec<Vec<SocketAddr>>,
    key: [u8; 32], // Secret key for randomized bucket hashing mapping
}

impl AddrMan {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        rand::thread_rng().fill(&mut key);

        Self {
            map_info: HashMap::new(),
            new_buckets: vec![Vec::new(); ADDRMAN_NEW_BUCKET_COUNT],
            tried_buckets: vec![Vec::new(); ADDRMAN_TRIED_BUCKET_COUNT],
            key,
        }
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let entries: Vec<PersistedAddrInfo> = self
            .map_info
            .values()
            .map(|e| PersistedAddrInfo {
                addr: e.addr.to_string(),
                source: e.source.to_string(),
                score: e.score,
                is_tried: e.is_tried,
                success_count: e.success_count,
                failure_count: e.failure_count,
            })
            .collect();

        let snapshot = AddrManSnapshot {
            key: self.key,
            entries,
        };

        let encoded = bincode::serialize(&snapshot)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        fs::write(path, encoded)?;
        debug!("AddrMan saved: {} entries", self.map_info.len());
        Ok(())
    }

    pub fn load_or_default(path: &Path) -> Self {
        if let Ok(data) = fs::read(path) {
            if let Ok(snapshot) = bincode::deserialize::<AddrManSnapshot>(&data) {
                let mut man = Self::new();
                man.key = snapshot.key;

                for entry in snapshot.entries {
                    if let (Ok(addr), Ok(source)) = (entry.addr.parse(), entry.source.parse()) {
                        let mut info = AddrInfo::new(addr, source);
                        info.score = entry.score.max(0);
                        info.is_tried = entry.is_tried;
                        info.success_count = entry.success_count;
                        info.failure_count = entry.failure_count;

                        man.map_info.insert(addr, info.clone());

                        if info.is_tried {
                            let bucket = man.get_tried_bucket(&addr);
                            if man.tried_buckets[bucket].len() < ADDRMAN_BUCKET_SIZE {
                                man.tried_buckets[bucket].push(addr);
                            }
                        } else {
                            let bucket = man.get_new_bucket(&addr, &source);
                            if man.new_buckets[bucket].len() < ADDRMAN_BUCKET_SIZE {
                                man.new_buckets[bucket].push(addr);
                            }
                        }
                    }
                }
                info!(
                    "Loaded AddrMan table from {} ({} entries)",
                    path.display(),
                    man.map_info.len()
                );
                return man;
            }
        }
        debug!(
            "No AddrMan table found or corrupted at {}, starting fresh",
            path.display()
        );
        Self::new()
    }

    fn get_group(ip: &IpAddr) -> Vec<u8> {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                vec![octets[0], octets[1]] // /16 prefix
            }
            IpAddr::V6(ipv6) => {
                let segments = ipv6.segments();
                vec![
                    (segments[0] >> 8) as u8,
                    (segments[0] & 0xff) as u8,
                    (segments[1] >> 8) as u8,
                    (segments[1] & 0xff) as u8,
                ] // /32 prefix for IPv6
            }
        }
    }

    /// Calculate the New table bucket based on Target Group and Source Group
    fn get_new_bucket(&self, target: &SocketAddr, source: &SocketAddr) -> usize {
        use std::collections::hash_map::DefaultHasher;
        let mut hasher = DefaultHasher::new();
        self.key.hash(&mut hasher);
        Self::get_group(&target.ip()).hash(&mut hasher);
        Self::get_group(&source.ip()).hash(&mut hasher);
        (hasher.finish() as usize) % ADDRMAN_NEW_BUCKET_COUNT
    }

    /// Calculate the Tried table bucket based on Target IP and Target Group
    fn get_tried_bucket(&self, target: &SocketAddr) -> usize {
        use std::collections::hash_map::DefaultHasher;
        let mut hasher = DefaultHasher::new();
        self.key.hash(&mut hasher);
        target.ip().hash(&mut hasher);
        Self::get_group(&target.ip()).hash(&mut hasher);
        (hasher.finish() as usize) % ADDRMAN_TRIED_BUCKET_COUNT
    }

    pub fn add(&mut self, addr: SocketAddr, source: SocketAddr) {
        if self.map_info.contains_key(&addr) {
            return;
        }

        let bucket = self.get_new_bucket(&addr, &source);
        if self.new_buckets[bucket].len() >= ADDRMAN_BUCKET_SIZE {
            // Simple eviction: remove the oldest/lowest scored
            let victim = self.new_buckets[bucket].remove(0);
            self.map_info.remove(&victim);
        }

        let info = AddrInfo::new(addr, source);
        self.map_info.insert(addr, info);
        self.new_buckets[bucket].push(addr);
    }

    pub fn add_many(&mut self, addrs: impl IntoIterator<Item = SocketAddr>, source: SocketAddr) {
        for addr in addrs {
            self.add(addr, source);
        }
    }

    pub fn good(&mut self, addr: SocketAddr) {
        let (is_tried, source) = {
            let Some(info) = self.map_info.get(&addr) else {
                return;
            };
            (info.is_tried, info.source)
        };

        if is_tried {
            return;
        }

        let new_bucket_id = self.get_new_bucket(&addr, &source);
        self.new_buckets[new_bucket_id].retain(|x| x != &addr);

        self.map_info.get_mut(&addr).unwrap().is_tried = true;

        let tried_bucket_id = self.get_tried_bucket(&addr);
        if self.tried_buckets[tried_bucket_id].len() >= ADDRMAN_BUCKET_SIZE {
            let victim = self.tried_buckets[tried_bucket_id].remove(0);

            let v_source = {
                if let Some(v_info) = self.map_info.get_mut(&victim) {
                    v_info.is_tried = false;
                    Some(v_info.source)
                } else {
                    None
                }
            };

            if let Some(v_src) = v_source {
                let v_new_bucket = self.get_new_bucket(&victim, &v_src);
                self.new_buckets[v_new_bucket].push(victim);
            }
        }

        self.tried_buckets[tried_bucket_id].push(addr);
        debug!("[{}] promoted to Tried table", addr);
    }

    pub fn record_success(&mut self, addr: SocketAddr) {
        if let Some(entry) = self.map_info.get_mut(&addr) {
            entry.score = (entry.score + 1).min(MAX_SCORE);
            entry.last_connected = Some(Instant::now());
            entry.last_attempt = Some(Instant::now());
            entry.success_count += 1;
            entry.banned_at = None;
            debug!("[{}] score → {} (success)", addr, entry.score);
        }
        self.good(addr); // Move to tried table upon success
    }

    pub fn record_failure(&mut self, addr: SocketAddr) {
        if let Some(entry) = self.map_info.get_mut(&addr) {
            entry.score = (entry.score - 1).max(MIN_SCORE - 1);
            entry.failure_count += 1;
            entry.last_attempt = Some(Instant::now());
            debug!("[{}] score → {} (failure)", addr, entry.score);

            if entry.score < MIN_SCORE {
                entry.banned_at = Some(Instant::now());
                debug!("[{}] banned for {}s", addr, BAN_DURATION.as_secs());
            }
        }
    }

    pub fn select_best_ipv4(&self, active: &[SocketAddr]) -> Option<SocketAddr> {
        let active_set: HashSet<_> = active.iter().collect();
        self.map_info
            .values()
            .filter(|e| e.is_connectable() && e.addr.is_ipv4() && !active_set.contains(&e.addr))
            .max_by_key(|e| (e.is_tried, e.score, e.success_count))
            .map(|e| e.addr)
    }

    pub fn select_best(&self, active: &[SocketAddr]) -> Option<SocketAddr> {
        let active_set: HashSet<_> = active.iter().collect();
        self.map_info
            .values()
            .filter(|e| e.is_connectable() && !active_set.contains(&e.addr))
            .max_by_key(|e| (e.is_tried, e.score, e.success_count))
            .map(|e| e.addr)
    }

    pub fn len(&self) -> usize {
        self.map_info.len()
    }

    pub fn connectable_count(&self) -> usize {
        self.map_info
            .values()
            .filter(|e| e.is_connectable())
            .count()
    }

    /// Returns a random sample of known addresses for `addr` responses.
    /// Max count recommended by Bitcoin protocol is 1000.
    pub fn get_random_sample(&self, count: usize) -> Vec<NetAddr> {
        let mut rng = rand::thread_rng();
        let all_connectable: Vec<_> = self
            .map_info
            .values()
            .filter(|e| e.is_connectable())
            .collect();

        if all_connectable.is_empty() {
            return Vec::new();
        }

        let sample_size = count.min(all_connectable.len());
        let mut indices: Vec<usize> = (0..all_connectable.len()).collect();

        // Simple shuffle and take
        use rand::seq::SliceRandom;
        indices.shuffle(&mut rng);

        indices
            .iter()
            .take(sample_size)
            .map(|&i| all_connectable[i].to_net_addr())
            .collect()
    }
}

impl Default for AddrMan {
    fn default() -> Self {
        Self::new()
    }
}
