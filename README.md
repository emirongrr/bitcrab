<div align="center">
  <img src="assets/banner.png" width="100%" alt="Bitcrab Epic Banner">
  <br>
  <h1>Bitcrab</h1>
  <p><strong>A High-Performance, Simplicity-Driven Bitcoin Full Node in Rust</strong></p>

  [![License: MIT](https://img.shields.io/badge/License-MIT-orange.svg)](https://opensource.org/licenses/MIT)
  [![Rust: 1.75+](https://img.shields.io/badge/Rust-1.75%2B-blue.svg)](https://www.rust-lang.org/)
  [![Network: Signet](https://img.shields.io/badge/Network-Signet-brightgreen.svg)](#)
</div>

---

Bitcrab is a minimal, educational, yet production-inspired Bitcoin full node implementation. The project prioritizes readability, correctness, and a clean architecture designed to address the inherent complexity of long-standing blockchain implementations.

## 🧭 Philosophy & Vision

Bitcrab is rooted in the **Cypherpunk** tradition. I believe that privacy, decentralization, and open-source transparency are non-negotiable for the future of money. By building an independent full node from scratch, Bitcrab empowers individuals to verify the network's state themselves, adhering to the core cypherpunk mantra: *"Cypherpunks write code."*

The development of Bitcrab is guided by three fundamental pillars:

1.  **Simplicity Over Complexity**: The architecture is rooted in the pursuit of radical simplicity. By writing minimal code and prioritizing architectural clarity, Bitcrab achieves a level of resilience and performance that bloated systems struggle to maintain. This approach ensures the codebase remains accessible, robust, and future-proof.
2.  **Client Diversity (Inspired by Ethereum)**: A robust blockchain requires multiple independent implementations to prevent systemic monoculture risks. Deeply influenced by the **Ethereum Vision**, Bitcrab strives to bring the same multi-client resilience to the Bitcoin ecosystem, ensuring the protocol remains defined by its universal specification rather than a single codebase.
3.  **Future-Ready Research & Innovation**: Adhering to these principles of simplicity enables rapid iteration on next-generation features, such as **Post-Quantum (PQ) Signatures**. Bitcrab addresses the urgent need for cryptographic evolution, serving as an experimental bed to ensure Bitcoin's long-term survival against emerging quantum threats.

Clarity and code readability are not just goals; they are the primary defenses against technical debt and systemic risk.

## 🎨 Design Principles

- **Effortless Setup**: Ensure smooth execution across all target environments.
- **Vertical Integration**: Maintain a minimal amount of dependencies.
- **Extensible Structure**: Built in a way that makes it easy to add new layers (e.g., L2 integration, research VMs) on top.
- **Simple Type System**: Avoid generics leaking across the codebase.
- **Few Abstractions**: Do not generalize until strictly necessary. Clarity is prioritized over complex abstractions.
- **Readability Over Optimization**: Maintainability is favored over premature optimizations.
- **Principled Concurrency**: Concurrency is utilized only where essential to maintain performance, keeping the system logic easy to reason about.

## 🚀 Key Features

- **Signet Native**: Optimized for the Bitcoin Signet network by default.
- **Component Isolation**: Decoupled P2P, Synchronization, and Storage layers using clean message-passing boundaries.
- **Parallel Header & Block Sync**: A streamlined pipeline that catches up headers instantly while downloading block bodies in parallel.
- **Modular Storage**: Hybrid storage engine with RocksDB metadata indexing and bit-for-bit compatible `blk*.dat` storage.
- **Real-time Monitoring**: Built-in Terminal UI (TUI) for network health and synchronization tracking.
- **Bitcoin Core Compatible RPC**: JSON-RPC 2.0 interface supporting essential audit and blockchain commands.

## 🛠️ Getting Started

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (latest stable version)
- Build tools (for RocksDB dependencies)

### Installation

```bash
git clone https://github.com/emirongrr/bitcrab.git
cd bitcrab
cargo build --release
```

### Running the Node

Start the Bitcrab node on the Signet network:

```powershell
cargo run --release -p bitcrab -- signet run
```

### Running the Monitor

Inspect your node's health in real-time:

```powershell
cargo run -p bitcrab-monitor
```

## 📂 Project Structure

- `cmd/`: Binary entry points (node and monitor).
- `crates/`: Modular core components.
  - `common/`: Core primitives (Hash, Block, Transaction).
  - `net/`: P2P wire protocol and Actor orchestration.
  - `storage/`: RocksDB indexer and flat-file persistence.
  - `consensus/`: Bitcoin rule validation.
- `docs/`: Technical specifications and API guides.

## 📡 RPC API

Bitcrab provides a Bitcoin Core compatible RPC interface on port `8332`.

| Method | Description |
| :--- | :--- |
| `getblockchaininfo` | Returns status of headers and block synchronization. |
| `getblock <hash>` | Retrieves full block data with transaction list. |
| `getpeerinfo` | Lists all active P2P connections and their metadata. |

For a full list of commands, see [RPC Guide](docs/rpc.md).

## 📚 References and acknowledgements

The following links, repositories, companies, and projects have been essential inspirations for Bitcrab:

- [Bitcoin Core](https://github.com/bitcoin/bitcoin) - The gold standard of Bitcoin implementations.
- [Ethereum Philosophy](https://ethereum.org/en/philosophy/) - For its commitment to decentralization and multi-client resilience.
- [Ethrex](https://github.com/lambdaclass/ethrex) - A primary inspiration for our architecture and mission.
- [Lambda Class](https://blog.lambdaclass.com/lambdas-engineering-philosophy/) - For their high-standard engineering philosophy.

## 📄 License

Bitcrab is licensed under the [MIT License](LICENSE).