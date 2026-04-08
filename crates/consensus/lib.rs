//! Bitcoin Consensus Engine.

pub mod chain_manager;
pub mod coins_view;
pub mod validator;

pub use bitcrab_common::types::undo::BlockUndo;
pub use chain_manager::{ChainManager, ChainMessage};
pub use coins_view::{CoinCacheEntry, CoinsView, CoinsViewCache, StoreCoinsView};
pub use validator::{TransactionValidator, ValidationError};
