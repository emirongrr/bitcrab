//! Bitcoin protocol constants.
//!
//! All consensus-critical constants in one place.
//! Changing any of these is a hard fork.
//!
//! Bitcoin Core equivalents:
//!   src/consensus/amount.h     — monetary constants
//!   src/consensus/consensus.h  — block/tx size limits
//!   src/script/script.h        — script limits
//!   src/chain.h                — time constants

// ---------------------------------------------------------------------------
// Monetary
// ---------------------------------------------------------------------------

/// Satoshis per bitcoin.
///
/// Bitcoin Core: `COIN = 100_000_000` in `src/consensus/amount.h`
pub const COIN: u64 = 100_000_000;

/// Maximum supply in satoshis.
///
/// Bitcoin Core: `MAX_MONEY = 21000000 * COIN` in `src/consensus/amount.h`
///
/// The actual circulating supply is slightly below this:
/// the genesis coinbase (50 BTC) was never added to the UTXO set.
pub const MAX_MONEY: u64 = 21_000_000 * COIN;

/// Block subsidy at genesis, in satoshis (50 BTC).
///
/// Bitcoin Core: `50 * COIN` in `src/kernel/chainparams.cpp`
pub const INITIAL_BLOCK_REWARD: u64 = 50 * COIN;

/// Number of blocks between each halving.
///
/// Bitcoin Core: `SUBSIDY_HALVING_INTERVAL = 210_000` in `src/consensus/params.h`
pub const HALVING_INTERVAL: u32 = 210_000;

/// Coinbase outputs cannot be spent until this many blocks later.
///
/// Bitcoin Core: `COINBASE_MATURITY = 100` in `src/consensus/consensus.h`
pub const COINBASE_MATURITY: u32 = 100;

// ---------------------------------------------------------------------------
// Block limits
// ---------------------------------------------------------------------------

/// Maximum block weight in weight units (4 MB equivalent).
///
/// Introduced by BIP-141 (SegWit).
/// Base data costs 4 weight units/byte, witness data costs 1.
///
/// Bitcoin Core: `MAX_BLOCK_WEIGHT = 4_000_000` in `src/consensus/consensus.h`
pub const MAX_BLOCK_WEIGHT: u64 = 4_000_000;

/// Pre-SegWit block size limit in bytes (1 MB).
///
/// Still enforced as the base size limit after SegWit.
///
/// Bitcoin Core: `MAX_BLOCK_SERIALIZED_SIZE = 4_000_000` in `src/consensus/consensus.h`
pub const MAX_BLOCK_BASE_SIZE: u64 = 1_000_000;

// Maximum number of transactions per block is not fixed — it is bounded
// by `MAX_BLOCK_WEIGHT`. A block of 1-input-1-output SegWit transactions
// at ~140 vbytes each fits roughly 28_000 transactions.

// ---------------------------------------------------------------------------
// Transaction limits
// ---------------------------------------------------------------------------

/// Minimum transaction size in bytes (stripped, no witness).
///
/// A transaction must have at least: version(4) + 1 input + 1 output + locktime(4).
/// The theoretical minimum is ~60 bytes.
///
/// Bitcoin Core: `MIN_TRANSACTION_WEIGHT` in `src/policy/policy.h`
pub const MIN_TRANSACTION_WEIGHT: u64 = 60;

/// Maximum standard transaction weight (400_000 WU = 100 KB vsize).
///
/// This is a policy limit, not consensus. Transactions above this
/// are not relayed by default nodes even if consensus-valid.
///
/// Bitcoin Core: `MAX_STANDARD_TX_WEIGHT = 400_000` in `src/policy/policy.h`
pub const MAX_STANDARD_TX_WEIGHT: u64 = 400_000;

// ---------------------------------------------------------------------------
// Script limits
// ---------------------------------------------------------------------------

/// Maximum script size in bytes.
///
/// Bitcoin Core: `MAX_SCRIPT_SIZE = 10_000` in `src/script/script.h`
pub const MAX_SCRIPT_SIZE: usize = 10_000;

/// Maximum number of non-push opcodes per script.
///
/// Bitcoin Core: `MAX_OPS_PER_SCRIPT = 201` in `src/script/script.h`
pub const MAX_OPS_PER_SCRIPT: usize = 201;

/// Maximum size of a single stack element in bytes.
///
/// Bitcoin Core: `MAX_SCRIPT_ELEMENT_SIZE = 520` in `src/script/script.h`
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// Maximum number of public keys per OP_CHECKMULTISIG.
///
/// Bitcoin Core: `MAX_PUBKEYS_PER_MULTISIG = 20` in `src/script/script.h`
pub const MAX_PUBKEYS_PER_MULTISIG: usize = 20;

/// Maximum combined stack depth (main + alt stack).
///
/// Bitcoin Core: `MAX_STACK_SIZE = 1000` in `src/script/interpreter.cpp`
pub const MAX_STACK_SIZE: usize = 1_000;

// ---------------------------------------------------------------------------
// Coinbase script
// ---------------------------------------------------------------------------

/// Minimum coinbase scriptSig length in bytes.
///
/// Bitcoin Core: `MIN_COINBASE_SCRIPTSIG_SIZE = 2` in `src/consensus/tx_check.cpp`
pub const MIN_COINBASE_SCRIPT_SIZE: usize = 2;

/// Maximum coinbase scriptSig length in bytes.
///
/// Bitcoin Core: `MAX_COINBASE_SCRIPTSIG_SIZE = 100` in `src/consensus/tx_check.cpp`
pub const MAX_COINBASE_SCRIPT_SIZE: usize = 100;

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

/// Maximum number of seconds a block timestamp can be ahead of network time.
///
/// Bitcoin Core: `MAX_FUTURE_BLOCK_TIME = 7200` in `src/chain.h`
pub const MAX_FUTURE_BLOCK_TIME: u32 = 7_200;

/// Number of blocks used to compute Median Time Past (BIP-113).
///
/// Bitcoin Core: `MEDIAN_TIME_SPAN = 11` in `src/chain.h`
pub const MEDIAN_TIME_SPAN: usize = 11;

/// Target seconds between blocks (10 minutes).
///
/// Bitcoin Core: `nPowTargetSpacing = 10 * 60` in `src/consensus/params.h`
pub const TARGET_BLOCK_TIME: u32 = 600;

/// Difficulty retarget interval in blocks (2 weeks at 10 min/block).
///
/// Bitcoin Core: `DifficultyAdjustmentInterval()` in `src/consensus/params.h`
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u32 = 2_016;

/// Target timespan for one difficulty period in seconds (2 weeks).
///
/// Bitcoin Core: `nPowTargetTimespan = 14 * 24 * 60 * 60` in `src/consensus/params.h`
pub const TARGET_TIMESPAN: u32 = DIFFICULTY_ADJUSTMENT_INTERVAL * TARGET_BLOCK_TIME;

// ---------------------------------------------------------------------------
// P2P network
// ---------------------------------------------------------------------------

/// Current P2P protocol version.
///
/// Bitcoin Core: `PROTOCOL_VERSION = 70015` in `src/version.h`
pub const PROTOCOL_VERSION: u32 = 70_015;

/// Minimum P2P protocol version we will connect to.
///
/// Bitcoin Core: `MIN_PEER_PROTO_VERSION = 31800` in `src/net_processing.cpp`
pub const MIN_PEER_PROTO_VERSION: u32 = 31_800;

/// Maximum number of headers per `headers` message.
///
/// Bitcoin Core: `MAX_HEADERS_RESULTS = 2000` in `src/net_processing.cpp`
pub const MAX_HEADERS_PER_MSG: usize = 2_000;

/// Maximum P2P message payload size (32 MB).
///
/// Bitcoin Core: `MAX_PROTOCOL_MESSAGE_LENGTH = 4 * 1024 * 1024`
/// Note: Bitcoin Core uses 4 MB; we use 32 MB to match current practice.
pub const MAX_MESSAGE_SIZE: u32 = 32 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Tests — constants must be self-consistent
// ---------------------------------------------------------------------------

