# Bitcrab JSON-RPC Reference

Bitcrab provides a subset of the Bitcoin Core JSON-RPC interface to allow external tools and services to interact with the node.

The RPC server listens on port `8332` by default.

---

## Blockchain Commands

### `getblockchaininfo`
Returns information about the current state of the blockchain.

**Example Request:**
```bash
curl --user username:password --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getblockchaininfo", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:8332/
```

**Response Fields:**
- `chain`: The active network (signet, main, etc.).
- `headers`: The number of block headers synced.
- `blocks`: The number of full block bodies downloaded and stored.
- `verificationprogress`: Estimated progress of synchronization (0.0 to 1.0).

---

### `getblockcount`
Returns the height of the most-work fully downloaded block.

---

### `getblockhash <height>`
Returns the hash of the block at the specified height.

---

### `getblock <hash>`
Retrieves full block information.

**Example Response:**
```json
{
  "hash": "0000000000000000000...",
  "confirmations": 12,
  "size": 124500,
  "height": 790123,
  "version": 536870912,
  "tx": [
    "txid1",
    "txid2"
  ],
  "time": 1614567890,
  "mediantime": 1614567400,
  "nonce": 12345678,
  "bits": "1a012345",
  "difficulty": 1.0,
  "chainwork": "0000000000000000000000000000000000000000000000000000000000000001",
  "previousblockhash": "..."
}
```

---

## Network Commands

### `getnetworkinfo`
Returns general info about the node's network status.

---

### `getpeerinfo`
Returns data about each connected network peer.

**Response Fields:**
- `id`: Unique peer ID.
- `addr`: IP address and port of the peer.
- `subver`: User agent string reported by the peer (e.g., `/Satoshi:27.0.0/`).
- `startingheight`: The height reported by the peer during the handshake.
- `conntime`: Time elapsed since the connection was established.
