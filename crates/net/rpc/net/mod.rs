use crate::rpc::{RpcApiContext, RpcHandler};
use crate::utils::RpcErr;
use serde::Serialize;
use serde_json::{json, Value};

pub struct GetNetworkInfoRequest;

impl RpcHandler for GetNetworkInfoRequest {
    fn parse(_params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        Ok(Self)
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        let counts = context.p2p.peer_table.get_connection_counts().await;

        let resp = GetNetworkInfoResponse {
            version: 260000,
            subversion: "/bitcrab:0.1.0/".to_string(),
            protocolversion: 70016,
            localservices: "0000000000000409".to_string(),
            localrelay: true,
            timeoffset: 0,
            networkactive: true,
            connections: counts.total(),
            connections_in: counts.inbound,
            connections_out: counts.outbound_full_relay + counts.block_relay_only + counts.feeler,
            networks: vec![],
            relayfee: 0.00001000,
            incrementalfee: 0.00001000,
            warnings: "".to_string(),
        };

        Ok(json!(resp))
    }
}

pub struct GetPeerInfoRequest;

impl RpcHandler for GetPeerInfoRequest {
    fn parse(_params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        Ok(Self)
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        let peers = context.p2p.peer_table.get_peers(None).await;

        let mut peer_list = Vec::new();

        for (i, handle) in peers.iter().enumerate() {
            peer_list.push(PeerInfoResponse {
                id: i as u32,
                addr: handle.addr.to_string(),
                services: format!("{:016x}", handle.services),
                lastsend: 0,
                lastrecv: 0,
                conntime: 0,
                subver: "/bitcrab:0.1.0/".to_string(),
                startingheight: 0,
                version: 70015,
                relaytxes: handle.conn_type.is_tx_relay_connection(),
                inbound: handle.conn_type == bitcrab_net::p2p::net_types::ConnectionType::Inbound,
                connection_type: handle.conn_type.to_string(),
            });
        }

        Ok(json!(peer_list))
    }
}

pub struct GetConnectionCountRequest;

impl RpcHandler for GetConnectionCountRequest {
    fn parse(_params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        Ok(Self)
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        let count = context.p2p.peer_table.get_peer_count().await;
        Ok(json!(count))
    }
}

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
    pub connections_in: usize,
    pub connections_out: usize,
    pub networks: Vec<Value>,
    pub relayfee: f64,
    pub incrementalfee: f64,
    pub warnings: String,
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
    pub inbound: bool,
    pub connection_type: String,
}
