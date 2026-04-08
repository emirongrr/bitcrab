# P2P Networking Architecture

The Bitcrab P2P system is designed as a high-performance, resilient, and strictly Bitcoin Core-compatible networking layer. It utilizes a **Supervised Actor Model** to manage peer connections and protocol state transitions.

## Architectural Overview

Bitcrab's networking logic is decoupled into specialized actors that communicate via asynchronous message passing. This ensures thread safety without the overhead of complex locking mechanisms.

### 1. PeerTableActor (The Registry)
Corresponds to `CConnman` in Bitcoin Core.
- **Role**: Central coordinator for all active connections.
- **Responsibilities**:
    - Maintains the set of connected peers.
    - Manages global misbehavior scoring and the ban list.
    - Interface for AddrMan (Address Manager) to persist and select peers.
- **Handle**: Accessed via the `PeerTable` cloneable handle.

### 2. PeerActor (The Peer Handler)
Corresponds to `CNode` in Bitcoin Core.
- **Role**: Manages the lifecycle of a single TCP connection.
- **Responsibilities**:
    - Handles low-level message framing and checksum verification.
    - Implements the version/verack handshake state machine.
    - Responds to `Ping` requests automatically to keep the connection alive.
    - Propagates inbound messages to the internal event bus.
- **Handle**: Accessed via the `PeerHandle`.

## Bitcoin Core Compatibility

The system is engineered for bit-for-bit wire compatibility and equivalent behavior with Bitcoin Core versions 22.0+.

### Protocol Framing
Bitcrab follows the standard 24-byte Bitcoin header format:
| Offset | Size | Name | Description |
|--------|------|------|-------------|
| 0 | 4 | Magic | Network identifier (e.g., `0x0A03CF40` for Signet) |
| 4 | 12 | Command | Null-padded ASCII command (e.g., `version\0\0\0\0\0`) |
| 16 | 4 | Length | Length of payload in bytes |
| 20 | 4 | Checksum | First 4 bytes of `SHA256(SHA256(payload))` |

### Misbehavior Scoring
Inspired by `CNode::Misbehave` in Bitcoin Core:
- Each peer starts with **100 reputation points**.
- Protocol violations (invalid checksums, oversized messages, etc.) deduct points.
- If a peer's score reaches **0**, they are automatically disconnected and their IP is **banned for 1 hour**.

### Handshake Flow
Bitcrab strictly enforces the standard Bitcoin handshake:
1. **Outbound**: Send `version` -> Receive `version` -> Send `verack` -> Receive `verack`.
2. **Inbound**: Receive `version` -> Send `version` -> Send `verack` -> Receive `verack`.
*Any message received before `verack` (except `version`) results in immediate disconnection.*

## Supervision & Safety
Every actor in the system is **supervised**. The background event loops are spawned within a controlled context:
- **Panic Safety**: If a `PeerActor` panics, the `PeerTable` detects the channel drop and cleans up the peer resources.
- **No Silent Failures**: All asynchronous tasks are designed to propagate errors back to their supervisors, ensuring that the node remains in a consistent state and diagnostic information is captured in logs.

## Observability
The P2P system integrates with `tracing` to provide real-time protocol monitoring.
- **Handshake Events**: Logs peer agent strings, versions, and starting heights.
- **Bannings**: Displays IP addresses and the reason for protocol bans.
- **Traffic**: Summarizes inbound and outbound command flow.
