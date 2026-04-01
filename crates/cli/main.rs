use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "bitcrab", version, about = "Minimal Bitcoin full node")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Connect to a signet peer and complete handshake
    Connect {
        #[arg(default_value = "seed.signet.bitcoin.sprovoost.nl:38333")]
        addr: String,
    },
    /// Download headers from signet peer
    Headers {
        #[arg(default_value = "seed.signet.bitcoin.sprovoost.nl:38333")]
        addr: String,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("bitcrab=debug".parse().unwrap())
                .add_directive("bitcrab_net=debug".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Connect { addr } => {
            use bitcrab_net::p2p::{connection::connect, message::Magic};
            match connect(&addr, Magic::Signet).await {
                Ok(conn) => {
                    info!(
                        "handshake complete — peer v{} '{}' height {}",
                        conn.peer_version, conn.peer_agent, conn.peer_height
                    );
                }
                Err(e) => {
                    eprintln!("error: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Headers { addr } => {
            use bitcrab_common::types::hash::BlockHash;
            use bitcrab_net::p2p::{connection::connect, message::Magic};

            // Signet genesis block hash.
            // Source: Bitcoin Core src/kernel/chainparams.cpp
            //
            // Display order (block explorers):
            //   0000013d4fef2d72d18ac33a8d0d6b2a8bd5f6c46a3f8c8a4e41c50fb337a3c
            //
            // We pass ZERO as the locator — this tells the peer to send headers
            // from the very beginning (genesis). Bitcoin Core behavior:
            // if locator hash is unknown, peer starts from genesis.
            //
            // Bitcoin Core: net_processing.cpp `ProcessGetHeaders()`
            let locator = vec![BlockHash::ZERO];

            let mut conn = match connect(&addr, Magic::Signet).await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("connect error: {}", e);
                    std::process::exit(1);
                }
            };

            match conn.get_headers(&locator).await {
                Ok(headers) => {
                    info!("got {} headers", headers.len());
                    if let Some(first) = headers.first() {
                        info!(
                            "first: hash={} time={} bits={:#010x}",
                            first.block_hash(),
                            first.time,
                            first.bits
                        );
                    }
                    if let Some(last) = headers.last() {
                        info!(
                            "last:  hash={} time={} bits={:#010x}",
                            last.block_hash(),
                            last.time,
                            last.bits
                        );
                    }
                }
                Err(e) => {
                    eprintln!("headers error: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}