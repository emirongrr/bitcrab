# Cleanup changelog

Dead code removed, and — separately — code that *looks* dead but must not be
removed. The distinction matters more than the removals do.

## The distinction

An unused item is dead only if nothing was ever supposed to call it. An unused
item that exists because a rule is **not implemented yet** is a record of a gap.
Deleting `bip65_height` would not clean anything up; it would delete the
evidence that CLTV activation is not enforced.

So this document has two lists. The first was removed. The second was left in
place deliberately, and needs sign-off before anyone touches it.

## Removed

### `crates/script`

| Item | Justification |
|---|---|
| `stack.rs` (`ScriptStack`, `StackError`) | Superseded by the rewritten interpreter, which operates on `Vec<Vec<u8>>` directly. No callers remained. |
| `ScriptInterpreter` facade (`interpreter.rs`) | A struct wrapping one call to `verify_script`. Zero callers after `engine.rs` and `signet.rs` moved to the free function. |
| `VerifyFlags::MANDATORY` | Mirrored Core's `MANDATORY_SCRIPT_VERIFY_FLAGS` but was never read. |
| `VerifyFlags::from_bits`, `VerifyFlags::without` | Constructor and set-difference helper with no callers. `bits()` is used (libbitcoinconsensus ABI); its inverse was not. |
| `ScriptExecutionData::annex_init` | Written once, never read. Core uses it only for a debug assertion. |

### `crates/net`

| Item | Justification |
|---|---|
| `p2p/metrics.rs` (whole module) | A global `Metrics` static with six atomic counters. Nothing incremented them and nothing read them. |
| `Connman::peer_count()` | Returned a hardcoded `0`. Worse than absent: a caller would have believed it. |
| `Connman::connect_a()` | Verbatim duplicate of `connect_addr`. |
| `Connman::connect_best()` | No callers; `ConnectionInitiator` drives peer selection through `PeerTable`. |
| `Connman::disconnect_all()` | No callers. |
| `SyncManager::double_stalling_timeout()` | No callers. Only the halving path is wired up, which meant the adaptive timeout could shrink but never grow — the asymmetry is what exposed it as dead. |

### `crates/common`

| Item | Justification |
|---|---|
| `ChainParams::is_segwit_active`, `is_bip34_active` | Predicates over activation heights that nothing called. The heights themselves are kept — see below. |

### Structural, not deletion

| Change | Justification |
|---|---|
| `SIGNET_ASSUME_VALID_HEIGHT` / `_HASH` in `chainstate.rs` | Hardcoded constants sitting next to `ConsensusParams::default_assume_valid`, which holds the same fact. Two sources of truth for one value. The hash from params is now resolved to a height through the block index, which also generalises the behaviour to every network instead of special-casing signet. |
| `opcode.rs` `From<u8>` | Converted arbitrary bytes into a sparse enum with `mem::transmute` — undefined behaviour for most of the opcode space. Replaced with a newtype over `u8`. Not dead code; unsound code. |

## Flagged — do not remove without sign-off

Every item below is currently unreferenced. Each one is unreferenced because a
**consensus rule is missing**, not because the item is obsolete. Removing them
would erase the only in-tree record that the rule is absent.

| Item | The rule that is missing |
|---|---|
| `ConsensusParams::bip65_height` | CLTV (BIP 65) activation is not gated by height. The script engine implements `OP_CHECKLOCKTIMEVERIFY` and the flag exists, but `GetBlockScriptFlags` has no equivalent — flags are a fixed set, not derived per block. |
| `ConsensusParams::bip66_height` | Same for strict DER (BIP 66). |
| `ConsensusParams::n_minimum_chain_work` | Not enforced. Core uses it to reject low-work header chains; without it a peer can flood cheap headers. |
| `constants::MEDIAN_TIME_SPAN` | BIP 113 median-time-past is not computed or checked. |
| `constants::MAX_FUTURE_BLOCK_TIME` | The two-hour future-timestamp limit is not checked. |
| `BlockError::TimestampTooFar`, `TimestampBelowMedianTimePast` | Typed errors for the two rules above. Defined, never constructed. |
| `Store::store_undo` output / absent `get_undo` | Undo data is written on every connected block and never read. There is no `DisconnectTip`, so the chain cannot reorganise. This is the largest single gap in the node. |
| `constants::MAX_STANDARD_TX_WEIGHT`, `MIN_TRANSACTION_WEIGHT` | Policy limits for mempool acceptance, which is not implemented. Policy, not consensus — lower risk, but same reasoning. |
| `ChainParams::bech32_hrp`, `Base58Type` prefixes | Address encoding is not implemented. Needed by any wallet-facing RPC. |
| `Blockchain::add_to_mempool`, `MempoolError` | The mempool exists as a type but is not wired into message handling; no `tx` message is processed. |

### Why `DIFFICULTY_ADJUSTMENT_INTERVAL` and `TARGET_TIMESPAN` are *not* flagged

These two constants are unused because `pow.rs` derives the interval from
`pow_target_timespan / pow_target_spacing` in the params, which is what Core
does. They are duplicated knowledge, not missing rules. They are candidates for
removal in a later pass; they are listed here only so the next reader does not
re-derive this.

## Verification

The workspace builds, `clippy --workspace --all-targets -- -D warnings` is
clean, and 321 tests pass on CI after every removal above.
