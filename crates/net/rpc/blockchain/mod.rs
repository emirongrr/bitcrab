use crate::rpc::{RpcApiContext, RpcHandler};
use crate::utils::RpcErr;
use serde::Serialize;
use serde_json::{json, Value};
use bitcrab_common::types::hash::BlockHash;
use bitcrab_common::wire::decode::{BitcoinDecode, Decoder};

pub struct GetBlockchainInfoRequest;

impl RpcHandler for GetBlockchainInfoRequest {
    fn parse(_params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        Ok(Self)
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        let magic = context.peer_manager.magic;
        
        // Header tip
        let tip_hash = context.store.get_best_block()?.unwrap_or_else(|| BlockHash::zero());
        let header_height = context.store.get_block_index(&tip_hash)?.map(|i| i.height.0).unwrap_or(0);

        // Block body tip
        let block_hash = context.store.get_block_tip()?.unwrap_or_else(|| BlockHash::zero());
        let block_height = context.store.get_block_index(&block_hash)?.map(|i| i.height.0).unwrap_or(0);

        let resp = GetBlockchainInfoResponse {
            chain: magic.to_string(), 
            blocks: block_height,
            headers: header_height,
            bestblockhash: block_hash.to_string(),
            difficulty: 1.0,
            mediantime: 0, 
            verificationprogress: (block_height as f64 / header_height.max(1) as f64).min(1.0),
            initialblockdownload: block_height < header_height,
            chainwork: "0".to_string(),
            size_on_disk: 0,
            pruned: false,
        };

        Ok(json!(resp))
    }
}

pub struct GetBlockCountRequest;
impl RpcHandler for GetBlockCountRequest {
    fn parse(_params: &Option<Vec<Value>>) -> Result<Self, RpcErr> { Ok(Self) }
    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        let block_hash = context.store.get_block_tip()?.unwrap_or_else(|| BlockHash::zero());
        let height = context.store.get_block_index(&block_hash)?.map(|i| i.height.0).unwrap_or(0);
        Ok(json!(height))
    }
}

pub struct GetBlockHashRequest { pub height: u32 }
impl RpcHandler for GetBlockHashRequest {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        let height = params.as_ref().and_then(|p| p.get(0)).and_then(|v| v.as_u64()).ok_or(RpcErr::MissingParam("height".into()))?;
        Ok(Self { height: height as u32 })
    }
    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        let hash = context.store.get_block_hash(self.height)?.ok_or_else(|| RpcErr::BadParams(format!("Height {} out of range", self.height)))?;
        Ok(json!(hash.to_string()))
    }
}

pub struct GetBlockRequest { pub hash: BlockHash }
impl RpcHandler for GetBlockRequest {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        let hash_str = params.as_ref().and_then(|p| p.get(0)).and_then(|v| v.as_str()).ok_or(RpcErr::MissingParam("hash".into()))?;
        let hash = hash_str.parse().map_err(|_| RpcErr::BadParams("invalid hash format".into()))?;
        Ok(Self { hash })
    }
    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        let raw = context.store.get_block(&self.hash)?.ok_or_else(|| RpcErr::BadParams("block not found".into()))?;
        let (block, _) = bitcrab_common::types::block::Block::decode(Decoder::new(&raw)).map_err(|e| RpcErr::Internal(format!("decode error: {}", e)))?;
        
        let txids: Vec<String> = block.transactions.iter().map(|tx| tx.txid().to_string()).collect();
        
        Ok(json!({
            "hash": self.hash.to_string(),
            "confirmations": 1,
            "version": block.header.version,
            "merkleroot": block.header.merkle_root.to_string(),
            "tx": txids,
            "time": block.header.time,
            "nonce": block.header.nonce,
            "bits": format!("{:08x}", block.header.bits),
            "previousblockhash": block.header.prev_hash.to_string(),
        }))
    }
}

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
