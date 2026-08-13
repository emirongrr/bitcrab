# Consensus Engine And Signature Experiment Specification

## Authority And Scope

Bitcoin Core C++ is Bitcrab's behavioral reference for consensus. Bitcrab's
Native engine is the production direction; the optional Core-reference engine
is an audit oracle for differential tests and benchmarks.

Bitcrab's actor and component boundaries must preserve Bitcoin wire data,
transaction IDs, block hashes, and consensus behavior.

References:

- Bitcoin Core `CheckInputScripts` and `ConnectBlock`: `src/validation.cpp`
- Bitcoin Core script interpreter: `src/script/interpreter.cpp`
- Bitcoin Core coins cache: `src/coins.h` and `src/coins.cpp`

## Selectable Engines

`ConsensusEngine` selects one script verification implementation:

- `Native`: Bitcrab's own `ScriptInterpreter`.
- `CoreReference`: optional `libbitcoinconsensus`, used as an oracle.

The node CLI accepts `--consensus-engine native` and
`--consensus-engine core-reference`. The application can be built without the
Core dependency using:

```text
cargo build -p bitcrab --no-default-features
```

Native is not yet proven equivalent for all active SegWit and Taproot rules.
Core-reference therefore remains the Signet audit default. A Native rule is
ready for production only after Bitcoin Core vector tests and differential
tests agree.

## Post-Quantum Experiments

Post-quantum signature experiments are deliberately outside consensus and
serialization. They must not change transactions, scripts, transaction IDs,
blocks, P2P messages, or accepted-chain behavior.

`SignatureExperimentVerifier` replays an identical workload of message
digests, signatures, and public keys through interchangeable verifiers. The
classic verifier provides a secp256k1 baseline. A future PQ verifier plugs into
the same interface and reports timing and acceptance counts.

No placeholder PQ algorithm is treated as real cryptography. Until an
experimental verifier is explicitly configured, PQ verification returns
`PostQuantumVerifierUnavailable`.

## Required Equivalence Tests

- Replay Bitcoin Core script test vectors through Native.
- Compare Native and Core-reference results for every supported script flag
  combination.
- Replay downloaded historical blocks without altering their serialized form.
- Record disagreements as hard failures with block, transaction, and input
  identifiers.
- Benchmark classic and PQ workloads separately from consensus acceptance.
