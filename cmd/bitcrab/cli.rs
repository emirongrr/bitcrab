use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;
use bitcrab_net::p2p::message::Magic;

#[derive(Parser, Debug)]
#[command(name = "bitcrab", version, about = "Minimal Bitcoin full node (Ethrex-style)")]
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
    },
    /// Connect to a peer and handshake (legacy tool)
    Connect { addr: String },
}
