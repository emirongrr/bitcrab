# Post-Quantum Bitcoin Execution Laboratory

## Research Goal

The laboratory answers counterfactual questions without claiming that unknown
historical owners produced post-quantum signatures:

- How large would Bitcoin blocks and the full chain be under a selected PQ
  signature and output construction?
- How would signing, verification, IBD, reindex, relay, mempool, UTXO, and
  wallet costs change?
- Which script forms can be translated faithfully, and which require explicit
  assumptions?
- How do classic-only, PQ-only, and hybrid migration policies compare?

Bitcoin Core C++ remains the reference for classic Bitcoin execution. NIST
FIPS 204 and FIPS 205 define the initial standardized PQ signature profiles.
BIP 360 and BIP 361 are draft Bitcoin migration references, not active
consensus rules.

## Required Experiment Modes

### 1. Shadow Replay

Read original Bitcoin blocks without modifying their bytes, transaction IDs,
merkle roots, or block hashes. For each signature check, create a deterministic
synthetic PQ authorization workload in a sidecar record.

Shadow replay can measure verification CPU, memory, synthetic signature bytes,
estimated relay bandwidth, and projected chain growth. It cannot prove that the
original transaction was authorized by the historical owner.

### 2. Counterfactual PQ Chain

Transform the economic transaction graph into a new PQ-native chain:

- preserve transaction order, input/output values, locktimes, sequences, and
  non-signature script conditions where translation is defined;
- replace signature authorization with deterministic synthetic PQ ownership;
- rewrite outpoints, transaction IDs, witness data, merkle roots, and block
  hashes;
- preserve original timestamps and block grouping for comparison.

This mode answers "what if Bitcoin had used this PQ design from genesis?" It is
not the historical Bitcoin chain and cannot preserve its proof of work. The
laboratory must mark transformed headers with a research-only replay seal or
mine against an explicitly trivial research target.

### 3. PQ-Native Live Chain

Start a private network from a PQ-specific genesis block and execute real
wallet-created PQ transactions. This mode measures end-to-end wallet, mempool,
relay, mining, validation, storage, and reorg behavior.

### 4. Hybrid Migration Simulation

Replay activation and migration policies with separate heights for:

- allowing PQ outputs;
- preferring or requiring PQ outputs;
- allowing hybrid classic-plus-PQ spends;
- restricting legacy output creation;
- restricting or rescuing legacy spends.

## Architecture

Keep Bitcoin transaction parsing and general script execution separate from
cryptographic authorization:

```text
Block/Transaction Decoder
        |
        v
Bitcoin Execution Engine
  value, UTXO, locktime, script flow
        |
        v
Authorization Engine
  Classic | PQ | Hybrid | Shadow
        |
        v
Signature Backend
  secp256k1 | ML-DSA | SLH-DSA | synthetic cost model
```

The execution engine must provide the exact signature message and context. The
authorization engine decides which proof is required. Signature backends only
sign or verify bytes; they must not know chainstate or mutate consensus state.

Suggested interfaces:

```text
ExecutionProfile
AuthorizationPolicy
SignatureScheme
SignatureSigner
SignatureVerifier
SyntheticKeyOracle
ScriptTranslator
ReplayEngine
ReplayMetrics
```

The current `SignatureExperimentVerifier` is a useful microbenchmark boundary,
but it is insufficient for chain replay because it lacks signing, script
translation, consensus cost, and transformed-transaction accounting.

## Deterministic Synthetic Ownership

Historical private keys are unavailable. Counterfactual replay therefore uses
a deterministic, domain-separated synthetic key oracle:

```text
synthetic_seed = Hash(
  "bitcrab-pq-replay-v1" ||
  experiment_manifest_hash ||
  ownership_identity
)
```

`ownership_identity` should preserve observable ownership reuse when possible:

- exposed public key for P2PK and revealed key spends;
- redeem/witness script identity for script-hash spends;
- output identity when no stable owner identity can be inferred.

This produces reproducible valid PQ signatures, but does not demonstrate
historical ownership. Every report must label these signatures as synthetic.

## Script Translation Rules

- P2PK, P2PKH, P2WPKH, and Taproot key-path spends can map to a PQ single-key
  authorization profile.
- Multisig can map to PQ `m-of-n`, but key and signature expansion must be
  measured explicitly.
- P2SH, P2WSH, and Tapscript may preserve non-signature conditions while
  translating signature checks.
- Unknown, non-standard, covenant-like, or deliberately unusual scripts cannot
  be translated automatically with a correctness claim. They must be marked
  opaque, unsupported, or handled by an explicit experiment rule.

## Consensus Questions The Lab Must Model

Introducing a PQ opcode or output type requires more than swapping a verifier:

- exact signature-message construction and domain separation;
- public-key and signature encoding rules;
- consensus limits for key, signature, stack-element, script, transaction, and
  block sizes;
- witness discount or a new weight schedule;
- PQ verification cost and sigop accounting;
- batch-verification semantics, if any;
- activation, reorg, mempool, relay, fee, and standardness policy;
- denial-of-service limits for worst-case valid and invalid proofs;
- hybrid downgrade resistance and algorithm agility.

Each experiment manifest must freeze these choices. Results from different
manifests are not directly comparable unless the changed parameters are named.

## Initial Algorithm Profiles

Use multiple profiles rather than declaring one winner:

- ML-DSA-44: 1,312-byte public key and 2,420-byte signature.
- ML-DSA-65: 1,952-byte public key and 3,309-byte signature.
- ML-DSA-87: 2,592-byte public key and 4,627-byte signature.
- SLH-DSA-128s: 32-byte public key and 7,856-byte signature.
- SLH-DSA-128f: 32-byte public key and 17,088-byte signature.

These sizes alone show why output commitments, witness placement, and weight
rules dominate the result. A small public key does not imply a small spend.

## Metrics

Record distributions, not only averages:

- transformed bytes, stripped bytes, witness bytes, weight, and virtual size;
- signatures and public keys per transaction and block;
- sign and verify latency: p50, p95, p99, maximum, and total;
- valid and invalid proof costs;
- peak memory, allocator bytes, cache hit rate, and verifier concurrency;
- UTXO entry size and total UTXO growth;
- block relay bytes, time-to-first-byte, and time-to-validation;
- IBD, reindex, reorg, and mempool admission throughput;
- storage amplification and compression ratio;
- unsupported-script count and value affected.

Reports must include the experiment manifest hash, source chain tip, code
revision, hardware, thread count, cache sizes, compiler settings, and backend
versions.

## What Can And Cannot Be Claimed

Can be measured:

- deterministic projected storage and bandwidth under a defined encoding;
- actual verification/signing cost of configured implementations;
- transformed-chain execution and sync performance;
- migration-policy effects under explicit assumptions.

Cannot be inferred from historical blocks:

- whether historical owners could or would migrate;
- the PQ public keys historical owners would choose;
- actual wallet behavior, fee market response, miner policy, or adoption;
- security of a new PQ implementation merely because it passes replay;
- preservation of historical txids, merkle roots, block hashes, or proof of
  work after signatures are changed.

## Implementation Order

1. Extend the implemented immutable authorization manifest and modeled
   byte/weight report with source-chain and environment provenance.
2. Add shadow replay with a byte-accurate synthetic cost backend.
3. Classify historical script/output types and report unsupported value.
4. Add deterministic synthetic key oracle and counterfactual transaction graph.
5. Add NIST known-answer-test harnesses before real PQ backends.
6. Add one real ML-DSA profile and one SLH-DSA profile behind optional,
   test/research-only features.
7. Add PQ-native regtest-style network and hybrid activation simulations.
8. Compare fresh sync, reindex, relay, reorg, and adversarial invalid-proof
   workloads.

Do not connect PQ experimental profiles to public Bitcoin networks or present
them as Bitcoin consensus.

## Implemented Comparison Command

The first research command compares authorization encodings without claiming
cryptographic execution measurements:

```text
bitcrab signet research compare \
  --signature-checks 1000 \
  --public-keys 1000 \
  --key-disclosure commit \
  --placement witness \
  --json
```

`signature-checks` and `public-keys` are separate because multisig, address
reuse, script-hash spends, and key commitments can produce different counts.
The report labels every projection as `modeled` and includes a canonical
authorization manifest ID so results produced with different authorization
assumptions cannot be silently combined. A future full `experiment_id` must
also bind the source chain tip, code revision, environment, and backend
versions.

Every scheme profile reports its size assumption. The initial PQ profiles use
the exact FIPS key and signature sizes without an additional Bitcoin sighash
byte; future opcode and signature-message experiments must revisit that choice.
