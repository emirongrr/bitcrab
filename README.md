# bitcrab

A minimal Bitcoin full node written in Rust.

Signet by default. Readable code, honest performance, no magic.

## Status

Early development. Not for production use.

## Design

- Types encode invariants — invalid states do not compile
- No unnecessary abstractions — complexity earns its place
- Every module has a companion spec in `docs/specs/`
- Benchmarks required before any performance claim

## Layout
```
crates/
  common/   primitives: Hash256, Amount, Block, Transaction
  net/      P2P wire protocol, peer management
  node/     chain state, block validation, UTXO set
  cli/      binary entry point
docs/
  specs/    Bitcoin protocol specifications
```