//! Consensus Validation Engine.

pub mod coins_view;
pub mod validator;
pub mod chain_manager;

pub use coins_view::{CoinsView, CoinsViewCache, StoreCoinsView, CoinCacheEntry};
pub use validator::{TransactionValidator, ValidationError};
pub use bitcrab_common::types::undo::BlockUndo;
pub use chain_manager::{ChainManager, ChainMessage};
