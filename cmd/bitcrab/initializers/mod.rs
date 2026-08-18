//! Node initialization logic for the bitcrab binary.

pub mod p2p;
pub mod storage;

use eyre::Result;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use bitcrab_common::ChainType;
use bitcrab_consensus::{
    chainstate::{run_chainstate_loop, ChainstateHandle},
    ChainstateManager, ConsensusEngine, ConsensusEngineKind,
};
use bitcrab_node::{Blockchain, Mempool};
use bitcrab_storage::Store;

use self::p2p::{init_p2p, P2PContext};
use self::rpc::init_rpc;
use self::storage::{compute_effective_datadir, init_store};

pub mod rpc;
/// This is what main.rs calls.
pub async fn init_node_service(
    datadir: Option<PathBuf>,
    chain: ChainType,
    _rpc_addr: Option<SocketAddr>,
    dbcache_mib: usize,
    consensus_engine: ConsensusEngineKind,
    script_checks: bool,
) -> Result<(PathBuf, CancellationToken, TaskTracker, Store)> {
    let effective_datadir = compute_effective_datadir(&datadir, chain);

    let (blockchain, tracker, cancel_token) = init_node(
        &effective_datadir,
        chain,
        dbcache_mib,
        consensus_engine,
        script_checks,
    )
    .await?;
    let store = blockchain.store.clone();

    // 4. P2P Layer
    let P2PContext { p2p, .. } = init_p2p(
        chain,
        store.clone(),
        blockchain.clone(),
        &tracker,
        cancel_token.clone(),
    );

    // 5. RPC Layer
    if let Some(addr) = _rpc_addr {
        init_rpc(
            addr,
            blockchain.clone() as Arc<dyn bitcrab_rpc::rpc::RpcNodeProvider>,
            p2p,
            &tracker,
            cancel_token.clone(),
        );
    }

    Ok((effective_datadir, cancel_token, tracker, store))
}

/// Initializes the core Bitcrab node stack (DB + Chainstate + Mempool).
pub async fn init_node(
    datadir: &std::path::Path,
    chain: ChainType,
    dbcache_mib: usize,
    consensus_engine: ConsensusEngineKind,
    script_checks: bool,
) -> Result<(Arc<Blockchain>, TaskTracker, CancellationToken)> {
    let cancel_token = CancellationToken::new();
    let tracker = TaskTracker::new();
    let params = chain.chain_params();
    let magic = params.magic;

    // 1. Storage
    let store = init_store(datadir, magic).await?;

    // 2. Chainstate Actor
    let (tx, rx) = tokio::sync::mpsc::channel(1024);
    let chainstate_handle = ChainstateHandle::new(tx);
    let chainstate_manager = ChainstateManager::new(
        store.clone(),
        chain,
        chainstate_handle.active_tip_state(),
        dbcache_mib.saturating_mul(1024 * 1024),
        ConsensusEngine::new(consensus_engine),
        script_checks,
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

    // 2. Load Genesis (Bitcoin Core: LoadGenesisBlock)
    blockchain
        .load_genesis()
        .await
        .map_err(|e| eyre::eyre!("Failed to load genesis: {}", e))?;

    // 3. Activate Best Chain (Resume sync from disk)
    blockchain
        .activate_best_chain()
        .await
        .map_err(|e| eyre::eyre!("Failed to activate best chain: {}", e))?;

    Ok((blockchain, tracker, cancel_token))
}
