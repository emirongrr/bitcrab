# Signet Sync And Performance Specification

## Scope

Bitcoin Core C++ is the consensus, P2P, chain-selection, and durability
reference. Bitcrab's internal actor-style boundaries must not change Bitcoin
behavior.

Core references:

- `src/validation.cpp`: `ProcessNewBlockHeaders`, `AcceptBlock`,
  `ActivateBestChain`, and `FlushStateToDisk`
- `src/net_processing.cpp`: peer download state and block requests
- `src/coins.h` and `src/coins.cpp`: coins cache
- `src/node/blockstorage.cpp`: flat block and undo files

## Implemented Pipeline

### Headers And Blocks

- Socket receive loops do not wait for complete header or block validation.
- Header acceptance remains serialized and batches RocksDB writes.
- The highest advertised eligible peer drives header sync.
- Blocks are downloaded ahead of the active chain and connected serially.
- Signet permits 64 blocks in flight per peer. Core uses 16; this is an
  intentional bounded Signet performance deviation.
- Requests not delivered within 30 seconds are released and temporarily
  excluded from the stalled peer. Exclusions are cleared only after 500 blocks
  of active-chain progress.

### Chainstate And Cache

- The live active tip is independent from the last persisted coins tip.
- `--dbcache <MiB>` configures a total memory budget; 75 percent currently
  funds the long-lived `CoinsViewCache`.
- Flushed unspent coins remain as clean cache hits. Dirty spent markers are
  removed, and clean entries are trimmed to the configured budget.
- Cache hit and miss counters are logged at chainstate flushes.
- Undo data is stored in `rev*.dat`; RocksDB stores positions and keyed state.

### Consensus Audit

- `--consensus-engine core-reference` uses optional `libbitcoinconsensus` as
  the Signet audit oracle.
- `--consensus-engine native` uses Bitcrab's own interpreter.
- Native is not yet proven equivalent for all active SegWit and Taproot rules.

## June 6, 2026 Audit Result

The audit datadir completed Signet at height `307683`: headers, downloaded
blocks, and active blocks all reported `307683`, with
`initialblockdownload=false`. The datadir occupied about 27.25 GB.

After a forced stop, the persisted coins tip was 403 blocks behind the flat
block files. The new release replayed those disk-resident blocks and returned
to the active tip in about 30 seconds. This demonstrates recovery, but also
shows that graceful shutdown flushing and crash tests remain necessary.

The zero-to-tip 10-20 minute target is not yet proven. A valid claim requires a
fresh datadir run with recorded elapsed time, peer delivery, CPU, memory,
RocksDB stalls, cache hit ratio, disk bytes, and final explorer comparison.

## Current Bottlenecks And Next Measurements

- Peer delivery can stall an entire early block window; timeout reassignment
  now avoids immediately recycling the same failed peer.
- UTXO random reads remain a likely validation bottleneck; measure cache hit
  ratios at several `dbcache` sizes during fresh sync.
- Separate block-index and chainstate into independent physical RocksDB
  databases without sharing Bitcoin Core's incompatible data directory.
- Add graceful-shutdown flush and process-kill crash tests around flat-file,
  block-index, undo, and chainstate commit boundaries.
- Add latency histograms for block download, script validation, UTXO lookup,
  RocksDB write/compaction stalls, and actor queue depth.
