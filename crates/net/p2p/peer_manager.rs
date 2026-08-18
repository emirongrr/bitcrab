use bitcrab_common::types::{block::Block, hash::BlockHash};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock, Semaphore};
use tracing::{debug, info, warn};

const HEADER_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

use bitcrab_common::constants::{MAX_HEADERS_PER_MSG, PROTOCOL_VERSION};

use crate::p2p::{
    messages::{
        getdata::GetData,
        getheaders::GetHeaders,
        headers::Headers,
        inv::{Inv, InvType},
        Message, Pong,
    },
    net_types::ConnectionType,
    node::{NodeHandle, NodeId},
    peer_table::PeerTable,
    sync::SyncManager,
};

/// Validation interface bridging Network layer to the Core validation logic (ChainstateManager).
#[async_trait::async_trait]
pub trait ValidationInterface: Send + Sync {
    async fn process_header(
        &self,
        header: &bitcrab_common::types::block::BlockHeader,
    ) -> Result<u32, String>;
    async fn process_headers(
        &self,
        headers: &[bitcrab_common::types::block::BlockHeader],
    ) -> Result<Vec<u32>, String> {
        let mut heights = Vec::with_capacity(headers.len());
        for header in headers {
            heights.push(self.process_header(header).await?);
        }
        Ok(heights)
    }
    async fn process_block(
        &self,
        block: &bitcrab_common::types::block::Block,
    ) -> Result<u32, String>;

    /// Build a block locator ending at genesis, rooted at `tip`.
    ///
    /// Bitcoin Core: `GetLocator()` in `src/chain.cpp`. The default returns the
    /// degenerate single-hash locator so test doubles need not model an index;
    /// real chain backends must override it or peers will restart every sync
    /// from genesis whenever our tip is not on their chain.
    fn get_block_locator(&self, tip: &bitcrab_common::types::hash::BlockHash) -> Vec<BlockHash> {
        vec![*tip]
    }

    /// Headers that follow the newest entry of `locator` we recognise.
    ///
    /// Bitcoin Core: `ProcessGetHeaders`. The locator is scanned newest-first
    /// for a hash on our best header chain; that is the fork point, and the
    /// answer is up to `limit` headers after it, stopping early if `stop_hash`
    /// is reached. An empty locator means "just the header named by
    /// `stop_hash`".
    ///
    /// Returns empty when we have nothing useful to say, which is also the
    /// right answer for a peer already at our tip.
    async fn headers_after_locator(
        &self,
        _locator: &[BlockHash],
        _stop_hash: BlockHash,
        _limit: usize,
    ) -> Vec<bitcrab_common::types::block::BlockHeader> {
        Vec::new()
    }

    /// A block body from disk, if we have it.
    ///
    /// `None` means the block is unknown or header-only, and the caller should
    /// answer `notfound` rather than stay silent.
    async fn block_by_hash(
        &self,
        _hash: &BlockHash,
    ) -> Option<bitcrab_common::types::block::Block> {
        None
    }
}

/// Represents the logical application state of a connected Peer.
///
/// Bitcoin Core: `Peer` struct in net_processing.cpp
pub struct Peer {
    pub id: NodeId,
    pub misbehavior_score: i32,
    pub last_height: u32,
    pub is_discouraged: bool,
    pub conn_type: ConnectionType,
}

impl Peer {
    pub fn new(id: NodeId, height: u32, conn_type: ConnectionType) -> Self {
        Self {
            id,
            misbehavior_score: 0,
            last_height: height,
            is_discouraged: false,
            conn_type,
        }
    }
}

enum MisbehaviorAction {
    Record { score: i32 },
    Discourage,
}

/// The Processing Layer for all Network messages.
///
/// Bitcoin Core: PeerManagerImpl in src/net_processing.cpp
#[derive(Clone)]
pub struct PeerManager {
    peer_table: PeerTable,
    validation: Arc<dyn ValidationInterface>,
    pub sync_manager: Arc<SyncManager>,
    peers: Arc<RwLock<HashMap<NodeId, Peer>>>,
    /// Serializes header acceptance without blocking a peer's socket receive loop.
    header_processing: Arc<Mutex<()>>,
    /// Bounds concurrent block acceptance while keeping socket reads responsive.
    block_processing: Arc<Semaphore>,
}

impl PeerManager {
    pub fn new(
        peer_table: PeerTable,
        validation: Arc<dyn ValidationInterface>,
        sync_manager: Arc<SyncManager>,
    ) -> Self {
        Self {
            peer_table,
            validation,
            sync_manager,
            peers: Arc::new(RwLock::new(HashMap::new())),
            header_processing: Arc::new(Mutex::new(())),
            block_processing: Arc::new(Semaphore::new(64)),
        }
    }

    /// Initializes peer state when a new connection is handshaked.
    ///
    /// Bitcoin Core: InitializeNode(CNode* pnode)
    pub async fn initialize_node(&self, id: NodeId, height: u32, conn_type: ConnectionType) {
        let mut map = self.peers.write().await;
        map.insert(id, Peer::new(id, height, conn_type));
    }

    /// Cleans up state when a node disconnects.
    ///
    /// Bitcoin Core: FinalizeNode(const CNode& node)
    pub async fn finalize_node(&self, id: &NodeId) {
        {
            let mut map = self.peers.write().await;
            map.remove(id);
        }
        self.peer_table.remove_peer(*id).await;
        self.sync_manager.on_peer_disconnect(*id);
    }

    /// Handle misbehaving nodes.
    ///
    /// Bitcoin Core: Misbehaving(const NodeId pnode, const int howmuch, const std::string& message)
    pub async fn misbehaving(&self, id: &NodeId, how_much: i32, message: &str) {
        let msg_suffix = if message.is_empty() {
            String::new()
        } else {
            format!(": {}", message)
        };

        let action = {
            let mut map = self.peers.write().await;
            let Some(peer) = map.get_mut(id) else {
                return;
            };

            let previous_score = peer.misbehavior_score;
            peer.misbehavior_score += how_much;

            if peer.misbehavior_score >= 100 && !peer.is_discouraged {
                warn!(
                    "[peer_manager] Misbehaving: peer={} ({} -> {}) DISCOURAGEMENT THRESHOLD EXCEEDED{}",
                    id, previous_score, peer.misbehavior_score, msg_suffix
                );
                peer.is_discouraged = true;
                MisbehaviorAction::Discourage
            } else {
                debug!(
                    "[peer_manager] Misbehaving: peer={} ({} -> {}){}",
                    id, previous_score, peer.misbehavior_score, msg_suffix
                );
                MisbehaviorAction::Record { score: how_much }
            }
        };

        match action {
            MisbehaviorAction::Record { score } => {
                self.peer_table.record_misbehavior(*id, score).await;
            }
            MisbehaviorAction::Discourage => {
                self.peer_table.record_critical_failure(*id).await;
            }
        }
    }

    pub async fn is_peer_discouraged(&self, id: &NodeId) -> bool {
        self.peers
            .read()
            .await
            .get(id)
            .map(|peer| peer.is_discouraged)
            .unwrap_or(false)
    }

    /// Central message processing router.
    ///
    /// Bitcoin Core: ProcessMessage(CNode& pfrom, const std::string& msg_type, ...)
    pub async fn process_message(&self, node_id: NodeId, handle: NodeHandle, msg: Message) {
        match msg {
            Message::Headers(h) => {
                // Bitcoin Core keeps socket I/O independent from validation work.
                // Header acceptance remains serialized, but the peer receive loop
                // can continue reading blocks while the batch is validated.
                let peer_manager = self.clone();
                tokio::spawn(async move {
                    peer_manager.on_headers(node_id, h, handle).await;
                });
            }
            Message::Block(b) => {
                let peer_manager = self.clone();
                tokio::spawn(async move {
                    let Ok(_permit) = peer_manager.block_processing.clone().acquire_owned().await
                    else {
                        return;
                    };
                    peer_manager.on_block(node_id, b).await;
                });
            }
            Message::Inv(i) => self.on_inv(node_id, handle, i).await,
            Message::Ping(ping) => self.on_ping(handle, ping.nonce).await,
            Message::NotFound(i) => self.on_not_found(node_id, i).await,
            Message::GetHeaders(g) => self.on_get_headers(node_id, handle, g).await,
            Message::GetData(g) => self.on_get_data(node_id, handle, g).await,
            _ => debug!(
                "[peer_manager] unhandled message type from {}: {:?}",
                node_id,
                msg.command()
            ),
        }
    }

    async fn on_headers(&self, peer_id: NodeId, headers: Headers, node: NodeHandle) {
        let _header_guard = self.header_processing.lock().await;
        self.sync_manager.finish_header_request(peer_id);

        if headers.headers.is_empty() {
            return;
        }

        info!(
            "[peer_manager] received {} headers from {}",
            headers.headers.len(),
            peer_id
        );

        let heights = match self.validation.process_headers(&headers.headers).await {
            Ok(heights) => heights,
            Err(e) => {
                warn!(
                    "[peer_manager] invalid header batch from {}: {}",
                    peer_id, e
                );
                self.misbehaving(&peer_id, 20, "non-connecting headers")
                    .await;
                return;
            }
        };

        let processed_in_batch = heights.len();

        // `process_headers` may accept only a prefix of the batch (a gap in the
        // chain truncates it). Pair the hash with its own height rather than
        // taking the last of each list independently, or a truncated batch
        // would advance the tip to a header we never accepted.
        let Some((last_header, last_height)) = headers
            .headers
            .iter()
            .zip(heights.iter().copied())
            .next_back()
        else {
            return;
        };
        let last_hash = last_header.block_hash();
        let last_time = last_header.time as u64;

        if last_hash != BlockHash::ZERO {
            self.sync_manager
                .update_headers_tip(last_hash, last_height, last_time);
            self.sync_manager.notify_work_available();
            info!(
                "[peer_manager] Header tip advanced: height {} from {} (Batch of {})",
                last_height, peer_id, processed_in_batch
            );
        }

        if headers.headers.len() == 2000 {
            debug!(
                "[peer_manager] full batch received, requesting next from {}",
                peer_id
            );
            if !self.sync_manager.try_begin_header_request(
                peer_id,
                last_hash,
                last_height,
                HEADER_REQUEST_TIMEOUT,
            ) {
                return;
            }
            let locator = self.validation.get_block_locator(&last_hash);
            if node
                .send(Message::GetHeaders(
                    crate::p2p::messages::getheaders::GetHeaders {
                        version: 70015,
                        locator,
                        stop_hash: BlockHash::ZERO,
                    },
                ))
                .await
                .is_err()
            {
                self.sync_manager.finish_header_request(peer_id);
            }
        }
    }

    async fn on_block(&self, peer_id: NodeId, block: Block) {
        let hash = block.header.block_hash();
        debug!("[peer_manager] received block {} from {}", hash, peer_id);

        match self.validation.process_block(&block).await {
            Ok(height) => {
                debug!(
                    "Successfully processed block: {} at height {}",
                    hash, height
                );
                self.sync_manager.halve_stalling_timeout();
                self.sync_manager.mark_block_received(&hash, peer_id);
            }
            Err(e) => {
                warn!("[peer_manager] invalid block from {}: {}", peer_id, e);
                self.sync_manager.mark_block_received(&hash, peer_id);
                self.misbehaving(&peer_id, 100, "invalid block data").await;
            }
        }
    }

    async fn on_not_found(&self, peer_id: NodeId, not_found: Inv) {
        warn!(
            "[peer_manager] {} items not found by node {}",
            not_found.inventory.len(),
            peer_id
        );

        for item in not_found.inventory {
            if item.inv_type == InvType::Block || item.inv_type == InvType::WitnessBlock {
                let block_hash = BlockHash::from_bytes(item.hash);
                debug!(
                    "[peer_manager] block {} not found by {}, releasing back to pool",
                    block_hash, peer_id
                );
                self.sync_manager.mark_block_received(&block_hash, peer_id);
            }
        }
    }

    /// A peer announced inventory it has.
    ///
    /// Bitcoin Core: the block branch of `ProcessMessage(INV)`. An announced
    /// block whose header we do not have yet means our chain is behind, so the
    /// useful reply is `getheaders` rather than `getdata` — headers-first sync
    /// means we want the header chain before any body.
    async fn on_inv(&self, peer_id: NodeId, node: NodeHandle, inv: Inv) {
        let announced: Vec<BlockHash> = inv
            .inventory
            .iter()
            .filter(|item| matches!(item.inv_type, InvType::Block | InvType::WitnessBlock))
            .map(|item| BlockHash::from_bytes(item.hash))
            .collect();

        if announced.is_empty() {
            return;
        }

        debug!(
            "[peer_manager] {} announced {} block(s)",
            peer_id,
            announced.len()
        );

        // Ask from our own tip, not from the announced hash: the announcement
        // may be several blocks ahead, and the locator is what lets the peer
        // work out everything we are missing.
        let (tip_hash, tip_height) = self.sync_manager.get_headers_tip();
        if !self.sync_manager.try_begin_header_request(
            peer_id,
            tip_hash,
            tip_height,
            HEADER_REQUEST_TIMEOUT,
        ) {
            return;
        }

        let locator = self.validation.get_block_locator(&tip_hash);
        if node
            .send(Message::GetHeaders(
                crate::p2p::messages::getheaders::GetHeaders {
                    version: PROTOCOL_VERSION as u32,
                    locator,
                    stop_hash: BlockHash::ZERO,
                },
            ))
            .await
            .is_err()
        {
            self.sync_manager.finish_header_request(peer_id);
        }
    }

    /// Serve `getheaders`.
    ///
    /// Bitcoin Core: `ProcessGetHeaders`. Without this a Core peer cannot sync
    /// from us at all — it asks, gets silence, and eventually disconnects.
    async fn on_get_headers(&self, peer_id: NodeId, node: NodeHandle, req: GetHeaders) {
        let headers = self
            .validation
            .headers_after_locator(&req.locator, req.stop_hash, MAX_HEADERS_PER_MSG)
            .await;

        debug!(
            "[peer_manager] serving {} headers to {}",
            headers.len(),
            peer_id
        );

        // An empty headers message is a valid answer meaning "you are at my
        // tip", and Core sends it, so do not skip the reply.
        let _ = node.send(Message::Headers(Headers { headers })).await;
    }

    /// Serve `getdata` for blocks.
    ///
    /// Bitcoin Core: `ProcessGetData`. Anything we cannot supply — an unknown
    /// block, a header we hold without its body, or a type we do not serve —
    /// goes back in a single `notfound`, because a peer waiting on a silent
    /// request stalls until its own timeout fires.
    async fn on_get_data(&self, peer_id: NodeId, node: NodeHandle, req: GetData) {
        let mut not_found = Vec::new();
        let mut served = 0usize;

        for item in req.inventory {
            match item.inv_type {
                InvType::Block | InvType::WitnessBlock => {
                    let hash = BlockHash::from_bytes(item.hash);
                    match self.validation.block_by_hash(&hash).await {
                        Some(block) => {
                            if node.send(Message::Block(block)).await.is_err() {
                                return;
                            }
                            served += 1;
                        }
                        None => not_found.push(item),
                    }
                }
                // Transaction relay is not implemented; saying so is better
                // than leaving the peer to time out.
                _ => not_found.push(item),
            }
        }

        if !not_found.is_empty() {
            debug!(
                "[peer_manager] served {} block(s) to {}, {} not found",
                served,
                peer_id,
                not_found.len()
            );
            let _ = node
                .send(Message::NotFound(Inv {
                    inventory: not_found,
                }))
                .await;
        } else if served > 0 {
            debug!("[peer_manager] served {} block(s) to {}", served, peer_id);
        }
    }

    async fn on_ping(&self, node: NodeHandle, nonce: u64) {
        debug!(
            "[peer_manager] responding to ping from {} with nonce {}",
            node.addr, nonce
        );
        let _ = node.send(Message::Pong(Pong { nonce })).await;
    }

    /// Trigger Initial Block Download sync with a specific peer.
    pub async fn sync_with_peer(&self, node: NodeHandle) {
        if self.sync_manager.is_ibd() {
            info!("[peer_manager] starting header sync with {}", node.addr);
            let (tip_hash, tip_height) = self.sync_manager.get_headers_tip();
            if !self.sync_manager.try_begin_header_request(
                node.addr,
                tip_hash,
                tip_height,
                HEADER_REQUEST_TIMEOUT,
            ) {
                return;
            }
            let locator = self.validation.get_block_locator(&tip_hash);
            if node
                .send(Message::GetHeaders(
                    crate::p2p::messages::getheaders::GetHeaders {
                        version: 70015,
                        locator,
                        stop_hash: BlockHash::ZERO,
                    },
                ))
                .await
                .is_err()
            {
                self.sync_manager.finish_header_request(node.addr);
            }
        }
    }
}
