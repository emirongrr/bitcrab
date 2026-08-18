use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "bitcrab", version, about = "Minimal Bitcoin full node")]
pub struct CLI {
    #[command(subcommand)]
    pub network: NetworkChoice,

    /// Data directory path (global override)
    #[arg(short, long, env = "BITCRAB_DATA_DIR", global = true)]
    pub datadir: Option<PathBuf>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum NetworkChoice {
    /// Use Bitcoin Mainnet
    Mainnet {
        #[command(subcommand)]
        command: Commands,
    },
    /// Use Bitcoin Signet
    Signet {
        #[command(subcommand)]
        command: Commands,
    },
    /// Use Bitcoin Testnet3
    Testnet3 {
        #[command(subcommand)]
        command: Commands,
    },
    /// Use Bitcoin Regtest
    Regtest {
        #[command(subcommand)]
        command: Commands,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Start the full node
    Run {
        /// RPC listen address
        #[arg(long, default_value = "127.0.0.1:8332")]
        rpc_addr: SocketAddr,
        /// Total database/cache memory budget in MiB.
        #[arg(long, default_value_t = 450)]
        dbcache: usize,
        /// Script consensus engine: native or core-reference.
        #[arg(long, default_value = "core-reference")]
        consensus_engine: String,
        /// Skip transaction script verification. Research/smoke-sync only.
        #[arg(long)]
        skip_script_checks: bool,
    },
    /// Connect to a peer and handshake (legacy tool)
    Connect { addr: String },
    /// Run reproducible classic/PQ research models.
    Research {
        #[command(subcommand)]
        command: ResearchCommands,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum ResearchCommands {
    /// Compare modeled authorization size and Bitcoin weight.
    Compare {
        /// Number of signature checks in the workload.
        #[arg(long)]
        signature_checks: u64,
        /// Number of public keys revealed or stored by the workload.
        #[arg(long)]
        public_keys: u64,
        /// Key disclosure model: commit or output.
        #[arg(long, default_value = "commit")]
        key_disclosure: String,
        /// Authorization placement: witness or stripped.
        #[arg(long, default_value = "witness")]
        placement: String,
        /// Commitment bytes per key when key-disclosure=commit.
        #[arg(long, default_value_t = 32)]
        commitment_bytes: u64,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}
