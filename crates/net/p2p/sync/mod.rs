pub mod block_downloader;
pub mod sync_manager;

use bitcrab_common::types::block::BlockIndex;
use bitcrab_common::types::hash::BlockHash;

pub trait SyncProvider: Send + Sync {
    fn get_next_block_hashes(&self, start_height: u32, limit: usize) -> Vec<BlockHash>;
    /// Build a block locator ending at genesis, rooted at `tip`.
    ///
    /// Bitcoin Core: `GetLocator()` in `src/chain.cpp`.
    fn get_block_locator(&self, tip: &BlockHash) -> Vec<BlockHash>;
    fn get_block_index(&self, hash: &BlockHash) -> Option<BlockIndex>;
    fn has_next_block_on_disk(&self, start_height: u32) -> bool;
    fn get_blocks_tip(&self) -> (BlockHash, u32);
    fn get_headers_tip(&self) -> (BlockHash, u32);
    fn activate_best_chain(&self) -> BoxFuture<'_, Result<(), String>>;
}

use futures::future::BoxFuture;

pub use sync_manager::SyncManager;
