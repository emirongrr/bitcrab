//! Bitcoin Consensus Engine.

pub mod chainstate;
pub mod coins;
pub mod validation;

pub use bitcrab_common::types::undo::BlockUndo;
pub use chainstate::{ChainstateManager, ChainstateMessage};
pub use coins::{CoinCacheEntry, CoinsView, CoinsViewCache, StoreCoinsView};
pub use validation::{TransactionValidator, ValidationError};
