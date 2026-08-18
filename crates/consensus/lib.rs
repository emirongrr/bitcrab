//! Bitcoin Consensus Engine.

pub mod chainstate;
pub mod coins;
pub mod engine;
pub mod pow;

#[cfg(all(test, feature = "differential-tests"))]
mod differential;
pub mod signet;
pub mod validation;

pub use bitcrab_common::types::undo::BlockUndo;
pub use chainstate::ChainstateManager;
pub use coins::{CoinCacheEntry, CoinsView, CoinsViewCache, StoreCoinsView};
pub use engine::{ConsensusEngine, ConsensusEngineKind};
pub use validation::{TransactionValidator, ValidationError};
