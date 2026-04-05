//! Storage table definitions for the bitcrab Bitcoin node.
//!
//! bitcrab mirrors Bitcoin Core's storage layout:
//!
//! - Raw block data is written to append-only flat files (`blk*.dat`),
//!   exactly as Bitcoin Core does. These files are never modified after
//!   a block is written.
//!
//! - RocksDB (one column family per table) is used where Bitcoin Core
//!   uses LevelDB: block index metadata and the UTXO set.
//!
//! - Undo data (`rev*.dat`) is not yet implemented.
//!
//! ## RocksDB tables
//!
//! ### Block index  (`blocks/index` in Bitcoin Core)
//!
//! | Table        | Key                       | Value                          |
//! |--------------|---------------------------|--------------------------------|
//! | `block_index`| `b` + 32-byte block hash  | Serialized `BlockIndex` record |
//! | `chain_meta` | `l`                       | Last block file number (4-byte LE u32) |
//! | `chain_meta` | `R`                       | Reindex flag (1-byte boolean)  |
//! | `chain_meta` | `F` + flag name           | Named feature flags            |
//!
//! ### UTXO set (`chainstate` in Bitcoin Core)
//!
//! | Table   | Key                            | Value                    |
//! |---------|--------------------------------|--------------------------|
//! | `utxos` | `C` + 32-byte txid + 4-byte vout | Compressed coin record |
//! | `utxos` | `B`                            | 32-byte best block hash  |

// ── Block index ───────────────────────────────────────────────────────────────

/// Block metadata index.
///
/// key   : [`PREFIX_BLOCK`] + 32-byte block hash
/// value : serialized `BlockIndex` (height, validation status, PoW bits,
///         `FlatFilePos` for block data and undo data)
///
/// Equivalent to the `b` records in Bitcoin Core's `blocks/index` LevelDB.
/// The actual block bytes live in `blk*.dat`, not here.
pub const BLOCK_INDEX: &str = "block_index";

/// UTXO set.
///
/// Two key formats coexist in this table (matching Bitcoin Core's chainstate):
///
/// - Coin   : [`PREFIX_COIN`] + 32-byte txid + 4-byte vout (LE u32)
///            → compressed coin (height, coinbase flag, scriptPubKey, amount)
///
/// - Best block : [`KEY_BEST_BLOCK`]
///               → 32-byte block hash of the block through which the UTXO
///                 set is consistent. Updated atomically with coin writes.
pub const UTXOS: &str = "utxos";

/// Miscellaneous chain-level metadata.
///
/// | Key bytes       | Meaning                                          |
/// |-----------------|--------------------------------------------------|
/// | `l` (0x6c)      | Last block file number (4-byte LE u32)           |
/// | `R` (0x52)      | Reindex-in-progress flag (0x01 = true)           |
/// | `F` + flag name | Named feature flags, e.g. `Ftxindex` (1-byte)   |
///
/// Equivalent to the non-`b` records in Bitcoin Core's `blocks/index` LevelDB.
pub const CHAIN_META: &str = "chain_meta";

// ── Table registry ────────────────────────────────────────────────────────────

/// Every column family opened at database startup.
///
/// Column families present on disk but absent from this list are dropped
/// on open — they belong to an older schema version.
pub const TABLES: [&str; 3] = [BLOCK_INDEX, UTXOS, CHAIN_META];

// ── Key prefixes (byte-for-byte compatible with Bitcoin Core) ─────────────────

/// Prefix for block metadata entries in [`BLOCK_INDEX`].
///
/// Full key: `0x62` + 32-byte block hash.
/// Matches the `b` prefix in Bitcoin Core's block index LevelDB.
pub const PREFIX_BLOCK: u8 = b'b';

/// Prefix for coin (UTXO) entries in [`UTXOS`].
///
/// Full key: `0x43` + 32-byte txid + 4-byte LE vout index.
/// Matches the `C` prefix in Bitcoin Core's chainstate LevelDB.
pub const PREFIX_COIN: u8 = b'C';

/// Key for the best block hash entry in [`UTXOS`].
///
/// Value: 32-byte block hash.
/// Matches the `B` key in Bitcoin Core's chainstate LevelDB.
pub const KEY_BEST_BLOCK: u8 = b'B';

/// Key for the last block file number in [`CHAIN_META`].
///
/// Value: 4-byte LE u32.
/// Matches the `l` key in Bitcoin Core's block index LevelDB.
pub const KEY_LAST_FILE: u8 = b'l';

/// Prefix for named feature flags in [`CHAIN_META`].
///
/// Full key: `0x46` + ASCII flag name (e.g. `b"Ftxindex"`).
/// Value: 1-byte boolean (0x01 = enabled, 0x00 = disabled).
/// Matches the `F` prefix in Bitcoin Core's block index LevelDB.
pub const PREFIX_FLAG: u8 = b'F';

/// Key for the reindex-in-progress flag in [`CHAIN_META`].
///
/// Value: 1-byte boolean (0x01 = reindexing, 0x00 = normal).
/// Matches the `R` key in Bitcoin Core's block index LevelDB.
pub const KEY_REINDEX: u8 = b'R';