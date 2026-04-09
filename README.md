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

Bitcrab is a manifestation of the **Cypherpunk** spirit in a world of increasing digital enclosure. We operate on the conviction that privacy, decentralization, and radical transparency are the only acceptable terms for the future of money. Bitcrab is not just a software client; it is an instrument of sovereignty, designed for those who refuse to trust and choose to verify.

We are committed to the fundamental principles that define a truly decentralized system:

- **Permissionless Openness**: Anyone, anywhere, should participate as an equal peer without seeking approval.
- **Radical Decentralization**: Minimizing dependence on any single actor, ensuring the network survives even if its creators vanish.
- **Censorship Resistance**: Stripping centralized entities of the power to interfere with individual sovereignty.
- **Total Auditability**: Anyone must be able to validate the rules for themselves—the primary mission of running a full node.
- **Credible Neutrality**: Building base-layer infrastructure that is demonstrably fair and transparent to all.
- **Tools, Not Empires**: We build interoperable tools that empower users, rather than walled gardens that trap them.
- **Cooperative Mindset**: Working together on shared research and libraries to create a positive-sum future for the entire ecosystem.

By building an independent full node from the first line of code, Bitcrab empowers the individual to become their own ultimate authority. We adhere to the core cypherpunk mantra: **"Cypherpunks write code."**

The development of Bitcrab is guided by three fundamental pillars:

1.  **Simplicity Over Complexity**: The architecture is rooted in the pursuit of radical simplicity. By writing minimal code and prioritizing architectural clarity, Bitcrab achieves a level of resilience and performance that bloated systems struggle to maintain. This approach ensures the codebase remains accessible, robust, and future-proof.
2.  **Client Diversity (Inspired by Ethereum)**: A robust blockchain requires multiple independent implementations to prevent systemic monoculture risks. Deeply influenced by the **Ethereum Vision**, Bitcrab strives to bring the same multi-client resilience to the Bitcoin ecosystem, ensuring the protocol remains defined by its universal specification rather than a single codebase.
3.  **Future-Ready Research & Innovation**: Adhering to these principles of simplicity enables rapid iteration on next-generation features, such as **Post-Quantum (PQ) Signatures**. Bitcrab addresses the urgent need for cryptographic evolution, serving as an experimental bed to ensure Bitcoin's long-term survival against emerging quantum threats.

Clarity and code readability are not just goals; they are the primary defenses against technical debt and systemic risk.

### 🧬 The Case for Evolution: Beyond the Era of Stasis

Bitcoin is often praised for its immutability and the extreme difficulty of changing its core protocol. While this conservatism has protected the network’s integrity for over a decade, we believe the perception that Bitcoin *cannot* or *should not* change is a systemic risk. Evolution is not a violation of Bitcoin’s principles; it is a requirement for its survival.

The primary catalyst for this shift will be the transition to the **Quantum Era**. The emergence of quantum computing represents an existential threshold that will demand more than just maintenance—it will demand a fundamental cryptographic transition. Bitcrab is founded on the conviction that Bitcoin must proactively prepare for this future. We serve as a research-first implementation designed to test **Post-Quantum (PQ) Signatures** and architectural upgrades, ensuring that when the pressure for change becomes inevitable, the community has a battle-tested path forward.

---

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
- [Vitalik Buterin](https://vitalik.eth.limo/general/2023/12/28/cypherpunk.html) - For defining the core cypherpunk values for the modern era.

## 📄 License

Bitcrab is licensed under the [MIT License](LICENSE).