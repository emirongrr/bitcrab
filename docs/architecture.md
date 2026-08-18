# Architecture

## Design Authority

Bitcoin Core C++ is the behavioral reference for Bitcoin consensus, P2P,
chain selection, and durability. Bitcrab's internal boundaries may differ, but
normal node execution must remain Bitcoin-compatible.

Research execution is isolated from production Bitcoin validation. Modeled,
synthetic, or counterfactual PQ rules must never be selected implicitly by the
normal node path.

## Crate Boundaries

| Crate | Responsibility |
| --- | --- |
| `bitcrab-common` | Bitcoin primitives, chain parameters, and wire encoding |
| `bitcrab-consensus` | Stateless and contextual Bitcoin validation |
| `bitcrab-script` | Script execution, signature backends, and pure research models |
| `bitcrab-net` | P2P framing, connection lifecycle, peers, and synchronization |
| `bitcrab-storage` | Keyed state and flat block/undo files |
| `bitcrab-node` | Adapters and composition between consensus, storage, and P2P |
| `bitcrab-rpc` | RPC methods over node interfaces |
| `bitcrab` | CLI, configuration, startup, shutdown, and research commands |

Consensus does not depend on networking. Research models do not mutate
chainstate. The node crate owns adapters between otherwise independent
components.

## Runtime Ownership

- Peer connection tasks own socket I/O.
- Peer and sync managers own bounded network state.
- Header and block validation preserve parent-before-child ordering.
- Chainstate owns active-chain mutation and the long-lived UTXO cache.
- Storage owns ordered flat-file and database writes.
- RPC reads through stable node and storage interfaces.

Expensive cryptographic validation may run concurrently, but result commitment
remains ordered and bounded. Shared mutexes should protect short metadata
operations, never socket I/O, database work, or signature verification.

## Research Boundary

```text
Bitcoin decoder and chain data
            |
            +--> Bitcoin consensus execution
            |
            +--> Research replay and classification
                      |
                      +--> modeled authorization profiles
                      +--> measured signature backends
                      +--> synthetic ownership oracle
                      +--> counterfactual PQ chain
```

Research reports carry an immutable manifest identity and label fields as
modeled, measured, or synthetic. Real PQ backends remain optional and
research-only until they pass official known-answer tests and independent
differential verification.

## Performance Principles

- Bound queues, caches, and in-flight work.
- Keep network reads independent from validation latency.
- Batch sequential database work without weakening durability boundaries.
- Measure cache hit rate, queue depth, storage stalls, and validation latency.
- Optimize from recorded profiles; do not hide consensus behavior behind
  speculative abstractions.
