//! BlockDownloadActor: Handles parallel block downloading from multiple peers.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use tokio::time::{interval, Duration, Instant};
use tracing::{debug, info, warn};

use crate::p2p::{
    actor::{Actor, ActorError, Context},
    messages::{
        getdata::GetData,
        inv::{InvType, InvVector},
        Message,
    },
    metrics::METRICS,
    peer::PeerHandle,
    peer_table::PeerTable,
};
use bitcrab_common::types::hash::BlockHash;
use bitcrab_common::wire::encode::BitcoinEncode;
use bitcrab_storage::Store;

pub enum BlockDownloadMessage {
    /// Announce new block hashes to download.
    DownloadBlocks(Vec<[u8; 32]>),
    /// Process incoming block body.
    BlockReceived(PeerHandle, bitcrab_common::types::block::Block),
    /// A new peer is available.
    PeerConnected(PeerHandle),
    /// Periodic check for timeouts and queue processing.
    Maintenance,
}

pub struct BlockDownloadActor {
    store: Store,
    peer_table: PeerTable,
    in_flight: HashMap<[u8; 32], (PeerHandle, Instant)>,
    queue: Vec<[u8; 32]>,
    /// Optional channel to notify when a block is successfully stored and ready for validation.
    on_block_available:
        Option<tokio::sync::mpsc::Sender<(BlockHash, bitcrab_common::types::block::BlockHeight)>>,
}

impl BlockDownloadActor {
    pub fn new(store: Store, peer_table: PeerTable) -> Self {
        Self {
            store,
            peer_table,
            in_flight: HashMap::new(),
            queue: Vec::new(),
            on_block_available: None,
        }
    }

    pub fn with_notifier(
        mut self,
        tx: tokio::sync::mpsc::Sender<(BlockHash, bitcrab_common::types::block::BlockHeight)>,
    ) -> Self {
        self.on_block_available = Some(tx);
        self
    }

    async fn process_queue(&mut self) {
        // If queue is empty, try to populate it from storage (Backward Sync)
        if self.queue.is_empty() && self.in_flight.is_empty() {
             self.populate_queue_from_store().await;
        }

        if self.queue.is_empty() {
            return;
        }

        let Ok(peers) = self.peer_table.get_peers().await else {
            return;
        };
        if peers.is_empty() {
            return;
        }

        let mut peer_idx = 0;
        while !self.queue.is_empty() && self.in_flight.len() < 128 {
            let hash = self.queue.remove(0);
            if self.in_flight.contains_key(&hash) {
                continue;
            }

            let peer = &peers[peer_idx % peers.len()];
            peer_idx += 1;

            let getdata = GetData {
                inventory: vec![InvVector {
                    inv_type: InvType::Block,
                    hash,
                }],
            };

            if peer.send(Message::GetData(getdata)).await.is_ok() {
                self.in_flight.insert(hash, (peer.clone(), Instant::now()));
            } else {
                self.queue.push(hash);
            }
        }
    }

    /// Look for headers that don't have a corresponding block body.
    async fn populate_queue_from_store(&mut self) {
        let Ok(Some(block_tip)) = self.store.get_block_tip() else {
             // If no blocks at all, start from GENESIS + 1
             self.fetch_next_batch(0).await;
             return;
        };

        let Ok(Some(idx)) = self.store.get_block_index(&block_tip) else { return; };
        self.fetch_next_batch(idx.height.0).await;
    }

    async fn fetch_next_batch(&mut self, start_height: u32) {
        debug!("[blocks] pulling missing block hashes starting from height {}", start_height + 1);
        for h in (start_height + 1)..(start_height + 512) {
            if let Ok(Some(hash)) = self.store.get_block_hash(h) {
                self.queue.push(hash.as_bytes().to_owned());
            } else {
                break;
            }
        }
    }

    async fn handle_block(
        &mut self,
        peer: PeerHandle,
        block: bitcrab_common::types::block::Block,
    ) -> Result<(), ActorError> {
        let hash_bytes = block.header.block_hash().as_bytes().to_owned();
        let hash = BlockHash::from_bytes(hash_bytes);

        if self.in_flight.remove(hash_bytes.as_slice()).is_some() {
            info!("[blocks] received block {} from {}", hash, peer.addr);

            let height = match self.store.get_block_index(&hash) {
                Ok(Some(idx)) => idx.height,
                _ => return Ok(()),
            };

            let raw_block = block.encode_message();
            if let Err(e) = self.store.store_block(block.header, height, raw_block).await {
                warn!("[blocks] failed to persist block {}: {}", hash, e);
            } else {
                METRICS.total_blocks_downloaded.fetch_add(1, Ordering::Relaxed);
                if let Some(ref tx) = self.on_block_available {
                    let _ = tx.send((hash, height)).await;
                }
            }
        }

        self.process_queue().await;
        Ok(())
    }
}

trait BlockExt { fn encode_message(&self) -> Vec<u8>; }
impl BlockExt for bitcrab_common::types::block::Block {
    fn encode_message(&self) -> Vec<u8> {
        use bitcrab_common::wire::encode::Encoder;
        self.encode(Encoder::new()).finish()
    }
}

impl Actor for BlockDownloadActor {
    type Message = BlockDownloadMessage;

    fn on_start(
        &mut self,
        ctx: &mut Context<Self>,
    ) -> impl std::future::Future<Output = Result<(), ActorError>> + Send {
        let handle = ctx.handle();
        async move {
            info!("[blocks] starting block download actor");
            tokio::spawn(async move {
                let mut interval = interval(Duration::from_secs(10));
                loop {
                    interval.tick().await;
                    let _ = handle.cast(BlockDownloadMessage::Maintenance).await;
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
                BlockDownloadMessage::DownloadBlocks(hashes) => {
                    self.queue.extend(hashes);
                    self.process_queue().await;
                }
                BlockDownloadMessage::BlockReceived(peer, block) => {
                    let _ = self.handle_block(peer, block).await;
                }
                BlockDownloadMessage::PeerConnected(_) => {
                    self.process_queue().await;
                }
                BlockDownloadMessage::Maintenance => {
                    let now = Instant::now();
                    let timed_out: Vec<_> = self.in_flight.iter()
                        .filter(|(_, (_, start))| now.duration_since(*start) > Duration::from_secs(60))
                        .map(|(hash, _)| *hash)
                        .collect();

                    for hash in timed_out {
                        if let Some((p, _)) = self.in_flight.remove(&hash) {
                            warn!("[blocks] block {} timed out from {}", hex::encode(hash), p.addr);
                            self.queue.push(hash);
                        }
                    }
                    self.process_queue().await;
                }
            }
            Ok(())
        }
    }
}
