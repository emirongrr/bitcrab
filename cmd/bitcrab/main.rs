use bitcrab::{
    cli::{Commands, NetworkChoice, ResearchCommands, CLI},
    init_tracing,
    initializers::init_node_service,
};
use clap::Parser;
use tracing::{info, warn};

use std::path::PathBuf;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // 1. Initialize Tracing (Global)
    init_tracing();

    let CLI { network, datadir } = CLI::parse();

    // 2. Extract Chain Identity
    let (chain, command) = match network {
        NetworkChoice::Mainnet { command } => (bitcrab_common::ChainType::Mainnet, command),
        NetworkChoice::Signet { command } => (bitcrab_common::ChainType::Signet, command),
        NetworkChoice::Testnet3 { command } => (bitcrab_common::ChainType::Testnet3, command),
        NetworkChoice::Regtest { command } => (bitcrab_common::ChainType::Regtest, command),
    };

    // 3. Handle Commands
    match command {
        Commands::Run {
            rpc_addr,
            dbcache,
            consensus_engine,
            skip_script_checks,
        } => {
            let consensus_engine = match consensus_engine.as_str() {
                "native" => bitcrab_consensus::ConsensusEngineKind::Native,
                "core-reference" => bitcrab_consensus::ConsensusEngineKind::CoreReference,
                other => {
                    return Err(eyre::eyre!(
                        "unknown consensus engine '{other}'; expected native or core-reference"
                    ));
                }
            };
            // Start the node service (Store + P2P + RPC)
            let (effective_datadir, cancel_token, tracker, _store) = init_node_service(
                datadir,
                chain,
                Some(rpc_addr),
                dbcache,
                consensus_engine,
                !skip_script_checks,
            )
            .await?;

            info!("[main] bitcrab node is running on {} chain", chain);
            info!("[main] data directory: {:?}", effective_datadir);
            if skip_script_checks {
                warn!(
                    "[main] transaction script checks are DISABLED; this is research/smoke-sync mode, not full validation"
                );
            }

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
            run_legacy_connect(addr, chain, datadir).await?;
        }
        Commands::Research { command } => run_research(command, chain)?,
    }

    Ok(())
}

fn run_research(command: ResearchCommands, chain: bitcrab_common::ChainType) -> eyre::Result<()> {
    match command {
        ResearchCommands::Compare {
            signature_checks,
            public_keys,
            key_disclosure,
            placement,
            commitment_bytes,
            json,
        } => {
            use bitcrab_script::{
                project_authorization, AuthorizationPlacement, ExperimentManifest, KeyDisclosure,
                SignatureScheme, RESEARCH_MODEL_VERSION,
            };

            let key_disclosure = match key_disclosure.as_str() {
                "commit" => KeyDisclosure::CommitUntilSpend { commitment_bytes },
                "output" => KeyDisclosure::PublicKeyInOutput,
                other => {
                    return Err(eyre::eyre!(
                        "unknown key disclosure '{other}'; expected commit or output"
                    ));
                }
            };
            let authorization_placement = match placement.as_str() {
                "witness" => AuthorizationPlacement::Witness,
                "stripped" => AuthorizationPlacement::Stripped,
                other => {
                    return Err(eyre::eyre!(
                        "unknown authorization placement '{other}'; expected witness or stripped"
                    ));
                }
            };
            let manifest = ExperimentManifest {
                signature_checks,
                revealed_public_keys: public_keys,
                key_disclosure,
                authorization_placement,
            }
            .validate()?;
            let baseline = project_authorization(manifest, SignatureScheme::EcdsaSecp256k1)?;
            let authorization_manifest_id = encode_hex(&manifest.manifest_id());
            let projections = SignatureScheme::ALL
                .into_iter()
                .map(|scheme| project_authorization(manifest, scheme))
                .collect::<Result<Vec<_>, _>>()?;

            if json {
                let rows = projections
                    .iter()
                    .map(|projection| {
                        serde_json::json!({
                            "scheme": projection.scheme.name(),
                            "standard_reference": projection.scheme.standard_reference(),
                            "size_assumption": projection.scheme.size_assumption(),
                            "signature_bytes": projection.signature_bytes,
                            "public_key_bytes": projection.public_key_bytes,
                            "output_commitment_bytes": projection.output_commitment_bytes,
                            "total_authorization_bytes": projection.total_authorization_bytes,
                            "authorization_weight": projection.authorization_weight,
                            "virtual_bytes": projection.virtual_bytes,
                            "weight_ratio_to_ecdsa": projection.ratio_to(baseline),
                            "evidence": "modeled"
                        })
                    })
                    .collect::<Vec<_>>();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "manifest": {
                            "authorization_manifest_id": authorization_manifest_id,
                            "model_version": RESEARCH_MODEL_VERSION,
                            "source_chain": chain.to_string(),
                            "signature_checks": signature_checks,
                            "public_keys": public_keys,
                            "key_disclosure": key_disclosure_name(key_disclosure),
                            "authorization_placement": placement_name(authorization_placement),
                            "commitment_bytes": commitment_bytes
                        },
                        "projections": rows
                    }))?
                );
                return Ok(());
            }

            println!("Bitcrab PQ authorization comparison (modeled)");
            println!(
                "authorization_manifest_id={authorization_manifest_id}, model={RESEARCH_MODEL_VERSION}, source_chain={chain}"
            );
            println!(
                "checks={signature_checks}, public_keys={public_keys}, disclosure={}, placement={}",
                key_disclosure_name(key_disclosure),
                placement_name(authorization_placement)
            );
            println!(
                "{:<18} {:>12} {:>12} {:>12} {:>10}",
                "scheme", "auth bytes", "weight", "vbytes", "vs ecdsa"
            );
            for projection in projections {
                println!(
                    "{:<18} {:>12} {:>12} {:>12} {:>9.2}x",
                    projection.scheme.name(),
                    projection.total_authorization_bytes,
                    projection.authorization_weight,
                    projection.virtual_bytes,
                    projection.ratio_to(baseline)
                );
            }
        }
    }
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn key_disclosure_name(disclosure: bitcrab_script::KeyDisclosure) -> &'static str {
    match disclosure {
        bitcrab_script::KeyDisclosure::CommitUntilSpend { .. } => "commit-until-spend",
        bitcrab_script::KeyDisclosure::PublicKeyInOutput => "public-key-in-output",
    }
}

fn placement_name(placement: bitcrab_script::AuthorizationPlacement) -> &'static str {
    match placement {
        bitcrab_script::AuthorizationPlacement::Witness => "witness",
        bitcrab_script::AuthorizationPlacement::Stripped => "stripped",
    }
}

async fn run_legacy_connect(
    addr: String,
    chain: bitcrab_common::ChainType,
    datadir: Option<PathBuf>,
) -> eyre::Result<()> {
    use bitcrab::initializers::storage::{compute_effective_datadir, init_store};
    use bitcrab_consensus::{
        chainstate::{run_chainstate_loop, ChainstateHandle},
        ChainstateManager,
    };
    use bitcrab_net::p2p::{
        addr_man::AddrMan, connman::Connman, peer_manager::PeerManager, peer_table::PeerTable,
        sync::SyncManager,
    };
    use bitcrab_node::{Blockchain, Mempool};

    use std::sync::Arc;
    use tracing::error;

    info!(
        "[connect] starting full-fidelity diagnostic connection to {}",
        addr
    );

    // 1. Initialize Real Stack (Persistent)
    let magic = chain.chain_params().magic;
    let effective_datadir = compute_effective_datadir(&datadir, chain);

    // Attempt to open the persistent store.
    // This will fail if another process (like the node) has it open.
    let store = match init_store(&effective_datadir, magic).await {
        Ok(s) => s,
        Err(e) => {
            return Err(eyre::eyre!(
                "Failed to open persistent store at {:?}: {}. Is the main node running?",
                effective_datadir,
                e
            ));
        }
    };

    // 2. Initialize Chainstate Actor
    let (tx, rx) = tokio::sync::mpsc::channel(1024);
    let chainstate_handle = ChainstateHandle::new(tx);
    let chainstate_manager = ChainstateManager::new(
        store.clone(),
        chain,
        chainstate_handle.active_tip_state(),
        450 * 1024 * 1024,
        bitcrab_consensus::ConsensusEngine::new(
            bitcrab_consensus::ConsensusEngineKind::CoreReference,
        ),
        true,
    );

    tokio::spawn(async move {
        run_chainstate_loop(chainstate_manager, rx).await;
    });

    let mempool = Arc::new(Mempool::new());

    let blockchain = Arc::new(Blockchain::new(
        store.clone(),
        chainstate_handle,
        mempool,
        chain,
    ));

    // 2. Load Genesis
    blockchain
        .load_genesis()
        .await
        .map_err(|e| eyre::eyre!("Genesis load failed: {}", e))?;

    // 3. Initialize Networking
    let peer_table = PeerTable::new(AddrMan::new());
    let sync = Arc::new(SyncManager::new());
    let handler = Arc::new(PeerManager::new(peer_table.clone(), blockchain, sync));
    let p2p = Connman::new(magic, peer_table, handler);

    // 4. Perform Handshake
    match p2p
        .connect(
            &addr,
            bitcrab_net::p2p::net_types::ConnectionType::OutboundFullRelay,
        )
        .await
    {
        Ok(peer) => {
            info!(
                "[connect] successfully connected and handshaked with peer: {}",
                peer.addr
            );
        }
        Err(e) => error!("[connect] connection failed: {:?}", e),
    }
    Ok(())
}
