use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::{info, error, warn};
use tracing_subscriber::EnvFilter;

use bitcrab_node::{init_node, NodeConfig, NodeHandles};
use bitcrab_net::p2p::message::Magic;


#[derive(Parser)]
#[command(name = "bitcrab", version, about = "Minimal Bitcoin full node")]
struct Cli {
    #[command(subcommand)]
    network: NetworkChoice,

    /// Data directory path (global override)
    #[arg(short, long, env = "BITCRAB_DATA_DIR", global = true)]
    datadir: Option<PathBuf>,
}

#[derive(Subcommand)]
enum NetworkChoice {
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

#[derive(Subcommand)]
enum Commands {
    /// Start the full node
    Run {
        /// RPC listen address
        #[arg(long, default_value = "127.0.0.1:8332")]
        rpc_addr: SocketAddr,
    },
    /// Connect to a peer and handshake (legacy tool)
    Connect {
        addr: String,
    },
}


#[tokio::main]
async fn main() -> eyre::Result<()> {
    // 1. Initialize Tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("bitcrab=info".parse().unwrap())
                .add_directive("bitcrab_net=info".parse().unwrap())
                .add_directive("bitcrab_rpc=info".parse().unwrap())
        )
        .init();

    let cli = Cli::parse();

    // 2. Handle Commands
    let (magic, command) = match cli.network {
        NetworkChoice::Mainnet { command } => (Magic::Mainnet, command),
        NetworkChoice::Signet { command } => (Magic::Signet, command),
        NetworkChoice::Regtest { command } => (Magic::Regtest, command),
    };

    let handles = match command {
        Commands::Run { rpc_addr } => {
            let config = NodeConfig {
                magic,
                rpc_addr: Some(rpc_addr),
                data_dir: cli.datadir,
            };

            init_node(config).await?
        }
        Commands::Connect { addr } => {
            run_legacy_connect(addr, magic).await?;
            return Ok(());
        }
    };

    let NodeHandles { cancel_token, tracker, .. } = handles;


    // 4. Wait for Signals (Graceful Shutdown)
    info!("[main] bitcrab node is running. Press Ctrl+C to stop.");

    // Support SIGTERM on Unix, or Ctrl+C on all
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    #[cfg(unix)]
    let sigterm_recv = sigterm.recv();
    #[cfg(not(unix))]
    let sigterm_recv = std::future::pending::<()>();
    
    tokio::select! {
        _ = ctrl_c => {
            info!("[main] Ctrl+C received, shutting down...");
        }
        _ = sigterm_recv => {
            info!("[main] SIGTERM received, shutting down...");
        }
    }



    // 5. Cleanup
    cancel_token.cancel();
    
    info!("[main] waiting for background tasks to finish...");
    // Wait for all tasks in the tracker to complete (with timeout)
    tokio::select! {
        _ = tracker.wait() => {
            info!("[main] all tasks finished cleanly.");
        }
        _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
            warn!("[main] shutdown timeout reached. Forced exit.");
        }
    }

    Ok(())
}

async fn run_legacy_connect(addr: String, magic: Magic) -> eyre::Result<()> {
    use bitcrab_net::p2p::connection::connect;
    match connect(&addr, magic).await {
        Ok((_manager, peer, _rx)) => {
            let info = peer.get_info().await?;
            info!("Connected to peer: {} v{} UA:{}", info.addr, info.version, info.user_agent);
        }
        Err(e) => error!("Connection failed: {}", e),
    }
    Ok(())
}
