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
        /// Peer address (default: signet DNS seed)
        #[arg(default_value = "seed.signet.bitcoin.sprovoost.nl:38333")]
        addr: String,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env()
            .add_directive("bitcrab=debug".parse().unwrap()))
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Connect { addr } => {
            use bitcrab_net::p2p::{connection::connect, message::Magic};

            info!("target: {}", addr);

            match connect(&addr, Magic::Signet).await {
                Ok(conn) => {
                    info!(
                        "✓ handshake complete — peer v{}, '{}', height {}",
                        conn.peer_version,
                        conn.peer_agent,
                        conn.peer_height
                    );
                }
                Err(e) => {
                    eprintln!("error: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}