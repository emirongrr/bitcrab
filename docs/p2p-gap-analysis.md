# P2P gap analysis against Bitcoin Core

What Bitcrab's peer-to-peer layer does, what Bitcoin Core does, and which of the
differences actually stop a sync. Priorities are assigned by consequence, not by
effort.

Reference: Bitcoin Core `src/net.cpp`, `src/net_processing.cpp`, `src/protocol.h`.

## Summary

Bitcrab can complete initial block download from a Core peer on signet. It
cannot **serve** anything, cannot stay at the tip reliably once IBD finishes,
and cannot reorganise. The blocking issues are P0 below.

| Priority | Meaning |
|---|---|
| **P0** | Blocks correct sync against a Core node, or against our own node |
| **P1** | Works today by luck or by polling; will fail under normal network conditions |
| **P2** | Divergence from Core with no current consequence for us |

---

## P0 — blocks sync

### 1. We serve nothing

`PeerManager::process_message` handles five inbound messages: `headers`,
`block`, `inv`, `ping`, `notfound`. There is no handler for `getheaders`,
`getdata`, `getaddr`, or `getblocks`.

We advertise `NODE_NETWORK | NODE_WITNESS` (`SERVICES = 0x09`) while answering
none of it. A Core peer that asks us for headers gets silence, waits, and
eventually drops us.

This is also the single hardest blocker for the end-to-end test the project
wants: **a Core node cannot sync from us**, so any test that stands up
`bitcoind` alongside Bitcrab and asserts they converge cannot be written yet.

Needed: `getheaders` → `headers`, `getdata` → `block`/`notfound`, and honouring
`sendheaders` for announcements.

### 2. No chain reorganisation

`activate_best_chain_inner` only walks forward from the current tip. Undo data
is written for every connected block and never read; there is no `DisconnectTip`
equivalent.

Signet reorganises. When it does, the node stops advancing permanently — it will
keep requesting a chain the peer no longer has.

### 3. `inv` announcements are ignored

`on_inv` collects the announced block hashes, logs a line claiming it is
"triggering get_data", and returns without sending anything.

After IBD the node stays current only because `BlockDownloader` re-issues
`getheaders` on a 250 ms tick. That is polling in place of the push mechanism
the protocol provides — it works, at the cost of latency and wasted round trips,
and it hides the missing handler.

### 4. `n_minimum_chain_work` is not enforced

Core refuses to commit to a header chain below this threshold. Without it a peer
can feed us an arbitrarily long chain of cheap headers and we will store all of
them. On signet, where difficulty is trivial, this is cheap to do.

---

## P1 — fragile

### 5. We never send `ping`

There is no keepalive and no ping timeout. Liveness is detected only by a 20
minute read timeout on the socket.

Core sends a ping every two minutes and disconnects a peer that has not ponged
within 20 minutes. A peer that goes silent but keeps its TCP connection open
holds one of our eight outbound slots for twenty minutes.

### 6. Handshake aborts on any decode failure

`Connman::handshake` runs `Message::decode(...)?` inside the loop. A known
command whose payload we mis-parse kills the connection instead of being
ignored. Core skips messages it does not understand.

Unknown *commands* are already handled (`Command::Unknown`); this is
specifically about known commands with unexpected payloads.

### 7. Wrong magic resyncs byte-by-byte

`Node::read_loop` advances one byte and retries on a magic mismatch. Core
disconnects. Our behaviour can silently resynchronise onto attacker-chosen
framing, and at best it burns CPU on a corrupted stream.

### 8. Misbehaviour scoring is not Core's

`misbehaving()` accumulates a score and discourages at a threshold, but the
score assignments do not match Core's, and Core has moved most of these to
immediate disconnect. Not blocking; means a peer that Core would drop, we keep.

---

## P2 — divergence without current consequence

### 9. Protocol version 70015

We advertise `PROTOCOL_VERSION = 70015`, which is coherent: below 70016 a peer
will not send `wtxidrelay` or `sendaddrv2`, so not implementing them is correct
rather than a gap.

The cost is BIP 155: we cannot learn Tor or I2P addresses, and on IPv6-heavy
networks the addressable peer set shrinks. Moving to 70016 requires handling
`sendaddrv2`, `addrv2` and `wtxidrelay` — do them together or not at all.

### 10. No compact block relay (BIP 152)

`sendcmpct` is parsed and ignored. Only relevant once the node is at the tip and
cares about propagation latency.

### 11. Transaction relay

No `tx`, `mempool`, or `feefilter` handling. The mempool type exists but nothing
feeds it. Not needed for block validation; needed before the node is useful to
anyone else on the network.

### 12. Single DNS seed for signet

`seed.signet.bitcoin.sprovoost.nl` only. Core ships several. If that seed is
down and `peers.dat` is empty, cold start fails with no diagnostic.

### 13. `MAX_MESSAGE_SIZE` is 4 MiB

Core's `MAX_PROTOCOL_MESSAGE_LENGTH` is 4,000,000 bytes exactly. Ours is
4,194,304. More permissive, so no valid message is rejected; a peer could send
us ~194 KB more than Core would accept.

---

## What is already correct

Worth recording so it is not re-audited:

- 24-byte message framing, checksum, and command validation match Core.
- Version/verack handshake ordering, nonce-based self-connection detection, and
  minimum peer protocol version.
- `SERVICES = NODE_NETWORK | NODE_WITNESS` is the right advertisement for a node
  that will serve blocks, once it does.
- Headers-first sync with a Core-compatible exponential block locator.
- Outbound connection quotas split into full-relay, block-relay-only and feeler,
  matching Core's structure.
- Block download windowing with in-flight tracking, per-peer workload limits,
  stall detection and reassignment.
- `ping`/`pong` responses (we answer; we just never initiate).

---

## Suggested order

The dependency chain runs: **serve → reorg → announce**.

1. **Serve `getheaders` and `getdata`.** Unblocks the e2e test where Core syncs
   from Bitcrab, which is the only real proof the wire behaviour is right.
2. **Reorg (`DisconnectTip`).** Undo data already exists; this is reading what we
   already write.
3. **`inv`-driven block fetch.** Small, and removes the polling workaround.
4. **`n_minimum_chain_work`.** Cheap, closes a real DoS vector.
5. **Ping keepalive and handshake robustness.** Both small.

Items 9 through 13 should wait until the node is a participant rather than a
consumer.
