use bitcrab::{
    cli::{CLI, Commands, NetworkChoice},
    initializers::{compute_effective_datadir, init_node_service},
    init_tracing,
};
use clap::Parser;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // 1. Initialize Tracing (Global)
    init_tracing();

    let CLI { network, datadir } = CLI::parse();

    // 2. Extract Network Params
    let (magic, command) = match network {
        NetworkChoice::Mainnet { command } => (bitcrab_net::p2p::message::Magic::Mainnet, command),
        NetworkChoice::Signet { command } => (bitcrab_net::p2p::message::Magic::Signet, command),
        NetworkChoice::Regtest { command } => (bitcrab_net::p2p::message::Magic::Regtest, command),
    };

    // 3. Handle Commands
    match command {
        Commands::Run { rpc_addr } => {
            // Start the node service (Store + P2P + RPC)
            let (effective_datadir, cancel_token, tracker, _store) =
                init_node_service(datadir, magic, Some(rpc_addr)).await?;

            info!("[main] bitcrab node is running on {} network", magic);
            info!("[main] data directory: {:?}", effective_datadir);

            // 4. Wait for Signals (Graceful Shutdown)
            let ctrl_c = tokio::signal::ctrl_c();

            #[cfg(unix)]
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
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
            tokio::select! {
                _ = tracker.wait() => {
                    info!("[main] all tasks finished cleanly.");
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                    warn!("[main] shutdown timeout reached. Forced exit.");
                }
            }
        }
        Commands::Connect { addr } => {
            run_legacy_connect(addr, magic).await?;
        }
    }

    Ok(())
}

async fn run_legacy_connect(addr: String, magic: bitcrab_net::p2p::message::Magic) -> eyre::Result<()> {
    use bitcrab_net::p2p::connection::connect;
    use tracing::{error};

    match connect(&addr, magic).await {
        Ok((_manager, peer)) => {
            let info = peer.get_info().await?;
            info!(
                "Connected to peer: {} v{} UA:{}",
                info.addr, info.version, info.user_agent
            );
        }
        Err(e) => error!("Connection failed: {}", e),
    }
    Ok(())
}
