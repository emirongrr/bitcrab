use crate::context::RpcContext;
use crate::methods::RpcError;
use serde::Serialize;
use serde_json::{json, Value};

#[derive(Debug, Serialize)]
pub struct GetNetworkInfoResponse {
    pub version: u32,
    pub subversion: String,
    pub protocolversion: u32,
    pub localservices: String,
    pub localrelay: bool,
    pub timeoffset: i32,
    pub networkactive: bool,
    pub connections: usize,
    pub networks: Vec<Value>,
    pub relayfee: f64,
    pub incrementalfee: f64,
    pub warnings: String,
}

pub async fn get_network_info(ctx: RpcContext) -> Result<Value, RpcError> {
    let connections = ctx.peer_manager.table.get_peer_count().await.unwrap_or(0);

    let resp = GetNetworkInfoResponse {
        version: 260000,
        subversion: "/bitcrab:0.1.0/".to_string(),
        protocolversion: 70016,
        localservices: "0000000000000409".to_string(),
        localrelay: true,
        timeoffset: 0,
        networkactive: true,
        connections,
        networks: vec![],
        relayfee: 0.00001000,
        incrementalfee: 0.00001000,
        warnings: "".to_string(),
    };

    Ok(json!(resp))
}

#[derive(Debug, Serialize)]
pub struct PeerInfoResponse {
    pub id: u32,
    pub addr: String,
    pub services: String,
    pub lastsend: u64,
    pub lastrecv: u64,
    pub conntime: u64,
    pub subver: String,
    pub startingheight: i32,
    pub version: i32,
    pub relaytxes: bool,
}

pub async fn get_peer_info(ctx: RpcContext) -> Result<Value, RpcError> {
    let peers = ctx
        .peer_manager
        .table
        .get_peers()
        .await
        .map_err(|e| RpcError {
            code: -32603,
            message: e.to_string(),
        })?;

    let mut peer_list = Vec::new();

    for (i, handle) in peers.iter().enumerate() {
        if let Ok(info) = handle.get_info().await {
            peer_list.push(PeerInfoResponse {
                id: i as u32,
                addr: info.addr.to_string(),
                services: format!("{:016x}", info.services),
                lastsend: 0,
                lastrecv: 0,
                conntime: info.conntime,
                subver: info.user_agent,
                startingheight: info.start_height,
                version: info.version,
                relaytxes: true,
            });
        }
    }

    Ok(json!(peer_list))
}

pub async fn get_connection_count(ctx: RpcContext) -> Result<Value, RpcError> {
    let count = ctx
        .peer_manager
        .table
        .get_peer_count()
        .await
        .map_err(|e| RpcError {
            code: -32603,
            message: e.to_string(),
        })?;
    Ok(json!(count))
}
