# Differential testing against libbitcoinconsensus

`bitcrab-script` is a native reimplementation of Bitcoin's script consensus
rules. Reimplementing consensus is only safe if the result is checked against
the reference implementation, so the crate ships a differential test suite that
runs the same transaction, the same spent outputs and the same verification
flags through both engines and asserts they reach the same verdict.

The reference engine is `libbitcoinconsensus`, linked through the
`bitcoinconsensus` crate and selected via `ConsensusEngineKind::CoreReference`.

## Running

```bash
cargo test -p bitcrab-consensus --features differential-tests
```

`core-reference` is **not** a default feature. The native engine is the
production path; the reference is a test oracle, and it does not link on every
toolchain — see below.

## Toolchain notes

### Windows / MSVC — does not link

On MSVC the link fails with unresolved `__imp_secp256k1_*` symbols:

```
libbitcoinconsensus.rlib(pubkey.o) : error LNK2019: unresolved external symbol
  __imp_secp256k1_ec_pubkey_parse referenced in function CPubKey::IsFullyValid
```

The `__imp_` prefix means the vendored C++ was compiled expecting to import
secp256k1 from a DLL, while the crate links it statically — the build does not
define `SECP256K1_STATIC` for the C++ half. This is a defect in the
`bitcoinconsensus` crate's build script, not in Bitcrab, and it is why the
feature is opt-in rather than default.

Everything except the differential tests builds and runs normally on Windows.

### WSL / Linux — works, with one workaround

`librocksdb-sys 0.16` vendors RocksDB 8.10, which predates GCC 13 and relies on
`<cstdint>` arriving transitively. On GCC 13 or newer it fails:

```
rocksdb/include/rocksdb/trace_record.h:63:11: error: 'uint64_t' does not name a type
note: 'uint64_t' is defined in header '<cstdint>'
```

Force-include the header rather than patching the vendored source:

```bash
export CXXFLAGS="-include cstdint"
cargo test -p bitcrab-consensus --features differential-tests
```

Set only `CXXFLAGS`; `<cstdint>` is C++-only and adding it to `CFLAGS` breaks
the C dependencies (lz4, zstd, zlib, bzip2).

When building the Windows checkout from WSL, point `CARGO_TARGET_DIR` at a
Linux-side path. Sharing `target/` across the two host triples thrashes the
build cache, and `/mnt/c` is slow enough that it matters:

```bash
cd /mnt/c/Users/<you>/.../bitcrab
CARGO_TARGET_DIR=$HOME/bitcrab-target CXXFLAGS="-include cstdint" \
  cargo test -p bitcrab-consensus --features differential-tests
```

## What is covered

Each case runs under several flag sets — `NONE`, `P2SH`, `CONSENSUS_SEGWIT` and
`CONSENSUS_TAPROOT` — so a rule that is only active under some flags is
exercised on both sides of its activation.

| Area | Cases |
|---|---|
| P2PKH | valid spend, corrupted signature, wrong public key |
| Bare multisig | 1-of-2, and the `CHECKMULTISIG` dummy under and without `NULLDUMMY` |
| P2SH | wrapped `CHECKSIG`, redeem-script hash mismatch |
| SegWit v0 | P2WPKH, P2WSH, wrong spent amount (BIP 143 commits to it), witness on a non-witness output |
| Taproot | key path valid and bogus, script path valid and uncommitted leaf, pre-taproot anyone-can-spend |
| Tapscript | `CHECKMULTISIG` disabled, `OP_SUCCESS80`, ordinary evaluation |
| Sighash | all six types: `ALL`, `NONE`, `SINGLE`, each with `ANYONECANPAY` |
| Structure | arithmetic, conditionals, unbalanced conditionals, disabled opcodes, stack underflow, operation limit, truncated push, hash preimage |
| Flags | `CLEANSTACK` and `MINIMALDATA` on and off |

## Agreement is on the verdict, not the reason

Bitcrab returns a typed `ScriptError` naming the exact rule that failed;
`libbitcoinconsensus` collapses every failure into one error code. The
assertions therefore compare accept/reject, not the reason. When a case does
disagree, Bitcrab's error is what tells you which rule diverged.
