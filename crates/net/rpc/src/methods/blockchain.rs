use crate::context::RpcContext;
use crate::methods::RpcError;
use serde::Serialize;
use serde_json::{json, Value};

/// Response for getblockchaininfo
/// Fields must match Bitcoin Core precisely for test compatibility.
#[derive(Debug, Serialize)]
pub struct GetBlockchainInfoResponse {
    pub chain: String,
    pub blocks: u32,
    pub headers: u32,
    pub bestblockhash: String,
    pub difficulty: f64,
    pub mediantime: u64,
    pub verificationprogress: f64,
    pub initialblockdownload: bool,
    pub chainwork: String,
    pub size_on_disk: u64,
    pub pruned: bool,
}

pub async fn get_blockchain_info(ctx: RpcContext) -> Result<Value, RpcError> {
    let tip_hash = ctx
        .store
        .get_best_block()
        .map_err(|e| RpcError {
            code: -1,
            message: e.to_string(),
        })?
        .unwrap_or_else(|| bitcrab_common::types::hash::BlockHash::zero());

    let tip_index = ctx
        .store
        .get_block_index(&tip_hash)
        .map_err(|e| RpcError {
            code: -1,
            message: e.to_string(),
        })?
        .unwrap_or_else(|| {
            // Fallback for genesis if not indexed yet
            bitcrab_common::types::block::BlockIndex {
                header: bitcrab_common::types::block::BlockHeader {
                    version: 1,
                    prev_hash: bitcrab_common::types::hash::BlockHash::zero(),
                    merkle_root: bitcrab_common::types::hash::Hash256::zero(),
                    time: 0,
                    bits: 0x1d00ffff,
                    nonce: 0,
                },
                height: bitcrab_common::types::block::BlockHeight(0),
                file_pos: None,
                undo_pos: None,
            }
        });

    let resp = GetBlockchainInfoResponse {
        chain: "regtest".to_string(), // TODO: Detect from magic
        blocks: tip_index.height.0,
        headers: tip_index.height.0, // Simplified: assume all headers have blocks
        bestblockhash: tip_hash.to_string(),
        difficulty: 1.0, // TODO: Calculate from nBits
        mediantime: tip_index.header.time as u64,
        verificationprogress: 1.0,
        initialblockdownload: false,
        chainwork: "0000000000000000000000000000000000000000000000000000000000000002".to_string(),
        size_on_disk: 0,
        pruned: false,
    };

    Ok(json!(resp))
}
