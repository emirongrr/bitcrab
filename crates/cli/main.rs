use clap::{Parser, Subcommand};
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;
use bitcrab_net::p2p::message::Magic;

#[derive(Parser)]
#[command(name = "bitcrab", version, about = "Minimal Bitcoin full node")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}
#[derive(clap::ValueEnum, Clone)]
enum NetworkChoice {
    Signet,
    Mainnet,
}
#[derive(Subcommand)]
enum Commands {
    /// Connect to a signet peer and complete handshake
    Connect {
        #[arg(default_value = "seed.signet.bitcoin.sprovoost.nl:38333")]
        addr: String,
    },
    /// Download first 2000 headers from signet peer
    Headers {
        #[arg(default_value = "seed.signet.bitcoin.sprovoost.nl:38333")]
        addr: String,
    },
    /// Download all headers until tip
    AllHeaders {
        #[arg(default_value = "seed.signet.bitcoin.sprovoost.nl:38333")]
        addr: String,
    },
    /// Start the P2P network and maintain connections
    StartNetwork {
        #[arg(value_enum, default_value = "signet")]
        network: NetworkChoice,
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
        Commands::StartNetwork { network } => {
            println!("DEBUG: CLI entered StartNetwork");
            use bitcrab_net::p2p::network::{NetworkConfig, start_network};

            let config = match network {
                NetworkChoice::Signet  => NetworkConfig::signet(),
                NetworkChoice::Mainnet => NetworkConfig::mainnet(),
            };

            info!("starting {} network", match config.magic {
                Magic::Signet => "signet",
                _             => "mainnet",
            });

            if let Err(e) = start_network(config).await {
                eprintln!("network error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Connect { addr } => {
            use bitcrab_net::p2p::{connection::connect, message::Magic};

            match connect(&addr, Magic::Signet).await {
                Ok((_manager, peer, _rx)) => {
                    info!(
                        "connected: {} v{} '{}' height={}",
                        peer.addr, peer.version, peer.user_agent, peer.start_height
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
            use bitcrab_net::p2p::{
                connection::connect,
                message::Magic,
                messages::{Message, getheaders::GetHeaders},
            };

            let (_manager, peer, mut rx) = match connect(&addr, Magic::Signet).await {
                Ok(m) => m,
                Err(e) => { eprintln!("connect error: {}", e); std::process::exit(1); }
            };

            let msg  = GetHeaders::from_tip(BlockHash::ZERO);
            peer.send(&msg).unwrap();

            loop {
                match tokio::time::timeout(tokio::time::Duration::from_secs(30), rx.recv()).await {
                    Ok(Some(Message::Headers(h))) => {
                        info!("got {} headers", h.headers.len());
                        if let Some(first) = h.headers.first() {
                            info!("first: hash={} time={} bits={:#010x}",
                                first.block_hash(), first.time, first.bits);
                        }
                        if let Some(last) = h.headers.last() {
                            info!("last:  hash={} time={} bits={:#010x}",
                                last.block_hash(), last.time, last.bits);
                        }
                        break;
                    }
                    Ok(Some(other)) => debug!("ignoring {}", other),
                    Ok(None) => { eprintln!("peer disconnected"); break; }
                    Err(e) => { eprintln!("recv timeout: {}", e); break; }
                }
            }
        }

        Commands::AllHeaders { addr } => {
            use bitcrab_common::types::{hash::BlockHash, block::BlockHeader};
            use bitcrab_net::p2p::{
                connection::connect,
                message::Magic,
                messages::{ Message, getheaders::GetHeaders},
            };

            let (_manager, peer, mut rx) = match connect(&addr, Magic::Signet).await {
                Ok(m) => m,
                Err(e) => { eprintln!("connect error: {}", e); std::process::exit(1); }
            };

            let mut all_headers: Vec<BlockHeader> = Vec::new();
            let mut tip = BlockHash::ZERO;

            loop {
                let msg = GetHeaders::from_tip(tip);
                peer.send(&msg).unwrap();

                let batch = loop {
                    match tokio::time::timeout(tokio::time::Duration::from_secs(30), rx.recv()).await {
                        Ok(Some(Message::Headers(h))) => break h.headers,
                        Ok(Some(other)) => debug!("ignoring {}", other),
                        Ok(None) => {
                            eprintln!("peer disconnected");
                            std::process::exit(1);
                        }
                        Err(e) => {
                            eprintln!("recv timeout: {}", e);
                            std::process::exit(1);
                        }
                    }
                };

                let count = batch.len();
                if count == 0 {
                    info!("sync complete — {} headers total", all_headers.len());
                    break;
                }

                tip = batch.last().unwrap().block_hash();
                all_headers.extend(batch);
                info!("downloaded {} headers, tip={}", all_headers.len(), tip);

                // Bitcoin Core sends max 2000 per response.
                // If we got fewer, we have reached the tip.
                if count < 2000 {
                    info!("sync complete — {} headers total", all_headers.len());
                    break;
                }
            }
        }
    }
}