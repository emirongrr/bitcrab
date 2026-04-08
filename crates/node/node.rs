//! Bitcoin node — orchestrates net and storage.
//!
//! Connects net (PeerManager) with storage (Store) via a sync pipeline:
//!   connect → getheaders → store headers → repeat
//!
//! Bitcoin Core: ChainstateManager + CConnman interaction in src/net_processing.cpp

use std::net::SocketAddr;
use std::sync::Arc;

use bitcrab_net::p2p::{
    addr_man::AddrMan,
    message::Magic,
    messages::{getheaders::GetHeaders, Message},
    peer_manager::PeerManager,
    peer_table::PeerTable,
};

use bitcrab_common::types::{block::BlockHeight, hash::BlockHash};
use bitcrab_storage::Store;

use thiserror::Error;
use tracing::{debug, info};

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum NodeError {
    #[error("storage error: {0}")]
    Storage(#[from] bitcrab_storage::StoreError),

    #[error("network error: {0}")]
    Net(#[from] bitcrab_net::p2p::errors::P2pError),

    #[error("no headers received from peer")]
    NoHeaders,

    #[error("channel closed")]
    ChannelClosed,
}

// ── Node ──────────────────────────────────────────────────────────────────────

/// The main node — owns storage and the peer manager.
pub struct Node {
    pub store: Store,
    pub peer_manager: Arc<PeerManager>,
}

impl Node {
    /// Create an in-memory node for testing.
    pub fn in_memory(magic: Magic) -> Result<Self, NodeError> {
        let store = Store::in_memory(magic).map_err(NodeError::Storage)?;
        let table = PeerTable::new(AddrMan::new());
        let peer_manager = Arc::new(PeerManager::new(magic, table));
        Ok(Self {
            store,
            peer_manager,
        })
    }

    /// Start the Bitcoin-compatible RPC server on a background task.
    pub fn start_rpc(&self, addr: SocketAddr) {
        let ctx = bitcrab_rpc::context::RpcContext::new(
            self.store.clone(),
            Arc::clone(&self.peer_manager),
        );

        tokio::spawn(async move {
            if let Err(e) = bitcrab_rpc::start_rpc_server(ctx, addr).await {
                tracing::error!("RPC server failed: {}", e);
            }
        });
    }

    /// Connect to a peer, send getheaders from our tip, store received headers.
    ///
    /// Returns the number of headers stored.
    ///
    /// Bitcoin Core: SendMessages() → getheaders in src/net_processing.cpp
    pub async fn sync_headers_from(&mut self, addr: SocketAddr) -> Result<usize, NodeError> {
        // Connect and handshake.
        let (peer, mut rx) = self.peer_manager.connect_addr(addr).await?;

        info!("[sync] connected to {addr}, starting header sync");

        // Build locator from our best block, or genesis if empty.
        let tip = self.store.get_best_block()?.unwrap_or(BlockHash::zero());

        let getheaders = GetHeaders::from_tip(tip);
        peer.send(Message::GetHeaders(getheaders))
            .await
            .map_err(|_e| bitcrab_net::p2p::errors::P2pError::ConnectionClosed)?;

        info!("[sync] sent getheaders (tip={})", tip);

        // Wait for the headers response.
        let headers_msg = loop {
            match rx.recv().await {
                Some(Message::Headers(h)) => break h,
                Some(other) => {
                    // Ignore non-headers messages (inv, ping, etc.)
                    debug!("[sync] ignoring message during header wait: {other}");
                }
                None => return Err(NodeError::ChannelClosed),
            }
        };

        let count = headers_msg.headers.len();
        info!("[sync] received {count} headers from {addr}");

        if count == 0 {
            return Err(NodeError::NoHeaders);
        }

        // Store each header.
        // We don't know exact heights yet — we derive them from chain position.
        // For now: start from best_height + 1, increment per header.
        let start_height = self
            .best_height()?
            .map(|h| h.next())
            .unwrap_or(BlockHeight::GENESIS);

        for (i, header) in headers_msg.headers.iter().enumerate() {
            let height = BlockHeight(start_height.0 + i as u32);
            let is_best = i == count - 1;
            self.store
                .store_header(header.clone(), height, is_best)
                .await?;
        }

        info!(
            "[sync] stored {count} headers, new tip height={}",
            start_height.0 + count as u32 - 1
        );

        Ok(count)
    }

    /// Current best block height from storage.
    pub fn best_height(&self) -> Result<Option<BlockHeight>, NodeError> {
        let Some(hash) = self.store.get_best_block()? else {
            return Ok(None);
        };
        let Some(entry) = self.store.get_block_index(&hash)? else {
            return Ok(None);
        };
        Ok(Some(entry.height))
    }

    /// Current best block hash from storage.
    pub fn best_hash(&self) -> Result<Option<BlockHash>, NodeError> {
        Ok(self.store.get_best_block()?)
    }
}

// ── Runner ────────────────────────────────────────────────────────────────────

use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

pub struct NodeConfig {
    pub magic: Magic,
    pub rpc_addr: Option<SocketAddr>,
    pub data_dir: Option<std::path::PathBuf>,
}

pub struct NodeHandles {
    pub node: Node,
    pub cancel_token: CancellationToken,
    pub tracker: TaskTracker,
}

/// Initialize the node and all background services.
///
/// Bitcoin Core: AppInitMain() in src/init.cpp
pub async fn init_node(config: NodeConfig) -> Result<NodeHandles, NodeError> {
    info!("[node] initializing bitcrab node");

    // 1. Storage
    let store = if let Some(path) = config.data_dir {
        Store::new(path, bitcrab_storage::EngineType::RocksDB, config.magic)
            .map_err(NodeError::Storage)?
    } else {
        Store::in_memory(config.magic).map_err(NodeError::Storage)?
    };

    // 2. Networking
    let table = PeerTable::new(AddrMan::new());
    let peer_manager = Arc::new(PeerManager::new(config.magic, table));

    let node = Node {
        store: store.clone(),
        peer_manager: peer_manager.clone(),
    };

    // 3. Orchestration
    let cancel_token = CancellationToken::new();
    let tracker = TaskTracker::new();

    // 4. P2P Networking Loop
    let p2p_manager = peer_manager.clone();
    let p2p_config = bitcrab_net::p2p::network::NetworkConfig {
        magic: config.magic,
        port: match config.magic {
            Magic::Signet => 38333,
            Magic::Mainnet => 8333,
            _ => 38333,
        },
    };
    let p2p_cancel = cancel_token.clone();
    tracker.spawn(async move {
        tokio::select! {
            res = bitcrab_net::p2p::network::run_p2p_maintenance(p2p_manager, p2p_config) => {
                if let Err(e) = res {
                    tracing::error!("P2P maintenance loop failed: {}", e);
                }
            }
            _ = p2p_cancel.cancelled() => {
                info!("[node] P2P networking shutting down");
            }
        }
    });

    // 5. RPC (Optional)
    if let Some(rpc_addr) = config.rpc_addr {
        let rpc_ctx = bitcrab_rpc::context::RpcContext::new(store.clone(), peer_manager.clone());

        let rpc_cancel = cancel_token.clone();
        tracker.spawn(async move {
            tokio::select! {
                res = bitcrab_rpc::start_rpc_server(rpc_ctx, rpc_addr) => {
                    if let Err(e) = res {
                        tracing::error!("RPC server failed: {}", e);
                    }
                }
                _ = rpc_cancel.cancelled() => {
                    info!("[rpc] shutting down");
                }
            }
        });
    }

    tracker.close();

    Ok(NodeHandles {
        node,
        cancel_token,
        tracker,
    })
}
