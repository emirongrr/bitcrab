# Storage Specification

The Bitcrab storage engine is designed for high-performance blockchain persistence, mirroring the data layout of Bitcoin Core while utilizing a modern asynchronous architecture to prevent disk I/O from blocking network and consensus operations.

## Architecture: Hybrid Service Model

Bitcrab utilizes a **Hybrid Service Architecture** that decouples data retrieval from data mutation.

### 1. Concurrent Read Handle (`Store`)
The storage layer provides a thin, thread-safe handle that allows multiple node components to read data simultaneously.
- **Direct Backend Access**: Reads from the block index and metadata are performed directly against the thread-safe database (RocksDB) or memory backend.
- **Lock-Free Indexing**: Retrieval of block headers and metadata does not require synchronization with the write worker, eliminating mailbox latency for read-heavy operations (e.g., P2P header responses).
- **Block File Reader**: Raw block data is read directly from disk via a dedicated reader component, allowing concurrent access to multiple `blk*.dat` files.

### 2. Sequential Write Worker
All mutations to the blockchain state and physical files are orchestrated by a single-threaded background worker.
- **Ordered Mutations**: Ensures that block storage, undo data, and index updates happen in a guaranteed sequential order.
- **Async Write Proxies**: Calls like `store_block` and `store_header` are asynchronous; they send messages to the worker and await a response via optimized channels.
- **File Rotation & Integrity**: The worker exclusively manages `blk*.dat` file rotation, pre-allocation, and `fsync` operations to ensure data integrity even during system failures.

## Data Layout

Bitcrab maintains 100% byte-for-byte compatibility with Bitcoin Core's physical data layout.

### Raw Block Storage (`blk*.dat`)
Blocks are stored in append-only flat files within the `blocks/` directory.
- **Record Format**: `[magic (4 bytes)] [size (4 bytes LE)] [data (size bytes)]`
- **File Rotation**: New files are created when the current file exceeds `MAX_BLOCK_FILE_SIZE` (default 128MB).
- **Pre-allocation**: Disk space is pre-allocated in chunks to minimize filesystem fragmentation.

### Undo Data (`rev*.dat`)
Stores the data necessary to "unspend" transactions when a block is disconnected from the main chain.
- Follows the same record format and rotation logic as block files.

## Database Schema (Metadata Index)

The metadata and UTXO set are stored in RocksDB using the following table structure:

| Table Name | Key Prefix | Meaning |
| :--- | :--- | :--- |
| `block_index` | `'b' + hash` | Block metadata, height, and file position (`FlatFilePos`). |
| `utxos` | `'C' + outpoint` | Unspent transaction outputs (Coins). |
| `utxos` | `'B'` | Hash of the current best block (tip). |
| `chain_meta` | `'l'` | Last block file number currently in use. |
| `chain_meta` | `'R'` | Reindex flag (used during node recovery). |

## Concurrency Model

- **MPSC Channel**: Nodes send write requests to the storage worker via a multi-producer, single-consumer channel.
- **Oneshot Replies**: The worker communicates the result of a write (including errors like disk-full) back to the caller via a unique oneshot channel.
- **Arc-based Sharing**: The database backend and block reader are shared via `Arc`, allowing safe, multi-threaded access for synchronous read operations.
