use crate::rpc::{RpcApiContext, RpcHandler};
use crate::utils::RpcErr;
use bitcrab_common::types::hash::BlockHash;
use bitcrab_common::wire::decode::{BitcoinDecode, Decoder};
use bitcrab_common::wire::encode::serialize;
use serde::Serialize;
use serde_json::{json, Value};

pub struct GetBlockchainInfoRequest;

impl RpcHandler for GetBlockchainInfoRequest {
    fn parse(_params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        Ok(Self)
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        let magic = context.p2p.magic;

        // Header tip (h)
        let header_hash = context
            .node
            .get_headers_tip()
            .await
            .map_err(RpcErr::Internal)?
            .unwrap_or_else(BlockHash::zero);
        let header_height = context
            .node
            .get_block_index_height(&header_hash)
            .await
            .map_err(RpcErr::Internal)?
            .unwrap_or(0);

        // Validated tip (b) - Reported as 'blocks' to match Bitcoin Core
        let best_hash = context
            .node
            .get_best_block()
            .await
            .map_err(RpcErr::Internal)?
            .unwrap_or_else(BlockHash::zero);
        let best_height = context
            .node
            .get_block_index_height(&best_hash)
            .await
            .map_err(RpcErr::Internal)?
            .unwrap_or(0);

        // Download tip (B) - Raw blocks on disk
        let disk_hash = context
            .node
            .get_block_tip()
            .await
            .map_err(RpcErr::Internal)?
            .unwrap_or_else(BlockHash::zero);
        let disk_height = context
            .node
            .get_block_index_height(&disk_hash)
            .await
            .map_err(RpcErr::Internal)?
            .unwrap_or(0);

        let resp = GetBlockchainInfoResponse {
            chain: magic.to_string(),
            blocks: best_height,
            headers: header_height,
            bestheaderhash: header_hash.to_string(),
            bestblockhash: best_hash.to_string(),
            disk_blocks: disk_height,
            difficulty: 1.0,
            mediantime: 0,
            verificationprogress: (best_height as f64 / header_height.max(1) as f64).min(1.0),
            initialblockdownload: best_height < header_height,
            chainwork: "0".to_string(),
            size_on_disk: 0,
            pruned: false,
        };

        Ok(json!(resp))
    }
}

pub struct GetBlockCountRequest;
impl RpcHandler for GetBlockCountRequest {
    fn parse(_params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        Ok(Self)
    }
    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        let block_hash = context
            .node
            .get_block_tip()
            .await
            .map_err(RpcErr::Internal)?
            .unwrap_or_else(BlockHash::zero);
        let height = context
            .node
            .get_block_index_height(&block_hash)
            .await
            .map_err(RpcErr::Internal)?
            .unwrap_or(0);
        Ok(json!(height))
    }
}

pub struct GetBlockHashRequest {
    pub height: u32,
}
impl RpcHandler for GetBlockHashRequest {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        let height = params
            .as_ref()
            .and_then(|p| p.first())
            .and_then(|v| v.as_u64())
            .ok_or(RpcErr::MissingParam("height".into()))?;
        Ok(Self {
            height: height as u32,
        })
    }
    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        let hash = context
            .node
            .get_block_hash(self.height)
            .await
            .map_err(RpcErr::Internal)?
            .ok_or_else(|| RpcErr::BadParams(format!("Height {} out of range", self.height)))?;
        Ok(json!(hash.to_string()))
    }
}

pub struct GetBlockRequest {
    pub hash: BlockHash,
    pub verbosity: u8,
}
impl RpcHandler for GetBlockRequest {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        let hash_str = params
            .as_ref()
            .and_then(|p| p.first())
            .and_then(|v| v.as_str())
            .ok_or(RpcErr::MissingParam("hash".into()))?;
        let hash = hash_str
            .parse()
            .map_err(|_| RpcErr::BadParams("invalid hash format".into()))?;
        let verbosity = params
            .as_ref()
            .and_then(|p| p.get(1))
            .and_then(Value::as_u64)
            .unwrap_or(1);
        if verbosity > 2 {
            return Err(RpcErr::BadParams("verbosity must be 0, 1, or 2".into()));
        }
        Ok(Self {
            hash,
            verbosity: verbosity as u8,
        })
    }
    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        let raw = context
            .node
            .get_block_raw(&self.hash)
            .await
            .map_err(RpcErr::Internal)?
            .ok_or_else(|| RpcErr::BadParams("block not found".into()))?;
        if self.verbosity == 0 {
            return Ok(json!(hex::encode(raw)));
        }

        let (block, dec) = bitcrab_common::types::block::Block::decode(Decoder::new(&raw))
            .map_err(|e| RpcErr::Internal(format!("decode error: {}", e)))?;
        dec.finish("Block")
            .map_err(|e| RpcErr::Internal(format!("decode error: {}", e)))?;

        let transactions = if self.verbosity == 2 {
            block
                .transactions
                .iter()
                .map(transaction_to_json)
                .collect::<Vec<_>>()
        } else {
            block
                .transactions
                .iter()
                .map(|tx| json!(tx.txid().to_string()))
                .collect::<Vec<_>>()
        };

        Ok(json!({
            "hash": self.hash.to_string(),
            "confirmations": 1,
            "version": block.header.version,
            "merkleroot": block.header.merkle_root.to_string(),
            "nTx": block.transactions.len(),
            "tx": transactions,
            "time": block.header.time,
            "nonce": block.header.nonce,
            "bits": format!("{:08x}", block.header.bits),
            "previousblockhash": block.header.prev_hash.to_string(),
        }))
    }
}

fn transaction_to_json(tx: &bitcrab_common::types::transaction::Transaction) -> Value {
    let raw = serialize(tx);
    let vin = tx
        .inputs
        .iter()
        .map(|input| {
            if input.previous_output.is_coinbase() {
                json!({
                    "coinbase": hex::encode(input.script_sig.as_bytes()),
                    "sequence": input.sequence,
                    "txinwitness": input.witness.iter().map(hex::encode).collect::<Vec<_>>(),
                })
            } else {
                json!({
                    "txid": input.previous_output.txid.to_string(),
                    "vout": input.previous_output.vout,
                    "scriptSig": {
                        "hex": hex::encode(input.script_sig.as_bytes()),
                    },
                    "sequence": input.sequence,
                    "txinwitness": input.witness.iter().map(hex::encode).collect::<Vec<_>>(),
                })
            }
        })
        .collect::<Vec<_>>();
    let vout = tx
        .outputs
        .iter()
        .enumerate()
        .map(|(n, output)| {
            json!({
                "value": output.value.to_sat() as f64 / 100_000_000.0,
                "n": n,
                "scriptPubKey": {
                    "hex": hex::encode(output.script_pubkey.as_bytes()),
                },
            })
        })
        .collect::<Vec<_>>();

    json!({
        "txid": tx.txid().to_string(),
        "hash": tx.wtxid().to_string(),
        "version": tx.version,
        "size": raw.len(),
        "locktime": tx.lock_time,
        "vin": vin,
        "vout": vout,
        "hex": hex::encode(raw),
    })
}

#[derive(Debug, Serialize)]
pub struct GetBlockchainInfoResponse {
    pub chain: String,
    pub blocks: u32,
    pub headers: u32,
    /// Bitcrab extension: hash corresponding to `headers`.
    pub bestheaderhash: String,
    pub bestblockhash: String,
    pub disk_blocks: u32,
    pub difficulty: f64,
    pub mediantime: u64,
    pub verificationprogress: f64,
    pub initialblockdownload: bool,
    pub chainwork: String,
    pub size_on_disk: u64,
    pub pruned: bool,
}
