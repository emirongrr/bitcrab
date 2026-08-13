# Bitcrab

Bitcrab is an independent Bitcoin full-node implementation and post-quantum
Bitcoin research platform written in Rust.

Bitcoin Core C++ is the behavioral reference for Bitcoin consensus, P2P, and
storage durability. Bitcrab's research layer is deliberately separated from
Bitcoin consensus so counterfactual experiments cannot silently change normal
node behavior.

## Research Scope

Bitcrab is being built to measure questions such as:

- How would standardized post-quantum signatures affect Bitcoin transaction,
  block, UTXO, and full-chain size?
- How do classic, PQ-only, and hybrid authorization policies compare?
- What are the effects on verification throughput, IBD, reindex, relay,
  mempool admission, and reorg handling?
- Which historical scripts can be translated faithfully, and which require
  explicit assumptions?

Research output must distinguish:

- **Measured** results from an executed cryptographic backend.
- **Modeled** results derived from declared sizes and Bitcoin weight rules.
- **Synthetic** authorization produced without historical private keys.

The project does not claim that synthetic PQ signatures prove historical
ownership or that experimental PQ rules are Bitcoin consensus.

## Current Status

- Signet headers and blocks can be synchronized and persisted.
- Bitcoin wire framing, peer lifecycle, block download, chainstate, flat block
  files, and RocksDB-backed indexes are implemented.
- Native script validation is incomplete for full SegWit and Taproot
  equivalence.
- Optional `libbitcoinconsensus` support is retained as a differential-testing
  oracle.
- PQ size and Bitcoin-weight comparison profiles are available.
- Real PQ signing/verifying backends and historical shadow replay remain
  research milestones.

## Reproducible PQ Comparison

Compare classic and standardized PQ authorization profiles:

```powershell
cargo run -p bitcrab -- signet research compare `
  --signature-checks 1000 `
  --public-keys 1000 `
  --key-disclosure commit `
  --placement witness
```

Emit machine-readable output:

```powershell
cargo run -p bitcrab -- signet research compare `
  --signature-checks 1000 `
  --public-keys 1000 `
  --json
```

The current comparison is a byte-accurate model using declared signature and
public-key sizes. It does not measure cryptographic execution time.

## Run The Node

```powershell
cargo run --release -p bitcrab -- signet run `
  --dbcache 1024 `
  --consensus-engine core-reference
```

Build without the optional Bitcoin Core reference engine:

```powershell
cargo build -p bitcrab --no-default-features
```

## Architecture

| Component | Responsibility |
| --- | --- |
| `crates/common` | Bitcoin primitives, chain parameters, and wire encoding |
| `crates/consensus` | Stateless and contextual Bitcoin validation |
| `crates/script` | Script execution, signature engines, and research models |
| `crates/net` | Bitcoin P2P framing, peers, and synchronization |
| `crates/storage` | RocksDB indexes and `blk*.dat` / `rev*.dat` files |
| `crates/node` | Composition adapters between storage, consensus, and network |
| `cmd/bitcrab` | Node and research CLI |

See:

- [PQ execution laboratory](docs/specs/research/pq-execution-lab.md)
- [Consensus engine and signature experiments](docs/specs/consensus/engine-and-signature-experiments.md)
- [Signet sync and performance](docs/specs/signet-sync-performance.md)
- [Storage specification](docs/specs/storage.md)

## Research Integrity

Every publishable experiment should record:

- source chain and tip;
- code revision;
- immutable experiment parameters;
- authorization manifest ID and full experiment ID;
- algorithm and backend version;
- modeled versus measured fields;
- hardware, compiler, thread count, and cache settings;
- unsupported scripts and affected value;
- raw result artifacts sufficient for independent reproduction.

Real PQ backends must pass official known-answer tests and differential tests
against an independent reference implementation before their results are
treated as cryptographic measurements.

## References

- [Bitcoin Core](https://github.com/bitcoin/bitcoin)
- [NIST FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205: SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [BIP 360: Pay-to-Merkle-Root](https://github.com/bitcoin/bips/blob/master/bip-0360.mediawiki)
- [BIP 361: Post Quantum Migration and Legacy Signature Sunset](https://github.com/bitcoin/bips/blob/master/bip-0361.mediawiki)

## License

[MIT](LICENSE)
