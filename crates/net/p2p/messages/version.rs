//! Version message — first message sent by both peers on connect.
//!
//! Bitcoin Core: `CVersionMessage` in src/protocol.h
//! Wire format: src/net_processing.cpp PushMessage(peer, NetMsgType::VERSION, ...)
//!
//! Wire layout (all LE except port which is BE):
//! version(4) services(8) timestamp(8)
//! recv_services(8) recv_addr(16) recv_port(2BE)
//! from_services(8) from_addr(16) from_port(2BE)
//! nonce(8) user_agent(varint+str) start_height(4) relay(1)

use std::time::{SystemTime, UNIX_EPOCH};
use bitcrab_common::wire::{
    Decoder, Encoder,
    encode::{VarStr, U16BE},
    error::DecodeError,
};
use crate::p2p::message::Command;
use super::BitcoinMessage;

#[derive(Debug, Clone)]
pub struct Version {
    pub version:       i32,
    pub services:      u64,
    pub timestamp:     i64,
    pub recv_services: u64,
    pub recv_addr:     [u8; 16],
    pub recv_port:     u16,
    pub from_services: u64,
    pub from_addr:     [u8; 16],
    pub from_port:     u16,
    pub nonce:         u64,
    pub user_agent:    String,
    pub start_height:  i32,
    pub relay:         bool,
}

impl Version {
    /// Bitcoin Core: PROTOCOL_VERSION = 70015 in src/version.h
    pub const PROTOCOL_VERSION: i32 = 70015;
    pub const USER_AGENT: &'static str = "/bitcrab:0.1.0/";
    /// NODE_NETWORK(1) | NODE_WITNESS(8)
    /// Bitcoin Core: src/net.h
    pub const SERVICES: u64 = 0x09;
    
    pub fn our_version_with_nonce(nonce: u64) -> Self {
        let mut v = Self::our_version();
        v.nonce = nonce;
        v
    }
    pub fn our_version() -> Self {
        Self {
            version:       Self::PROTOCOL_VERSION,
            services:      Self::SERVICES,
            timestamp:     SystemTime::now()
                               .duration_since(UNIX_EPOCH)
                               .unwrap()
                               .as_secs() as i64,
            recv_services: 0,
            recv_addr:     [0u8; 16],
            recv_port:     0,
            from_services: Self::SERVICES,
            from_addr:     [0u8; 16],
            from_port:     0,
            nonce:         make_nonce(),
            user_agent:    Self::USER_AGENT.to_string(),
            start_height:  0,
            relay:         true,
        }
    }
}

impl BitcoinMessage for Version {
    const COMMAND: Command = Command::Version;

    fn encode(&self) -> Vec<u8> {
        Encoder::new()
            .encode_field(&self.version)
            .encode_field(&self.services)
            .encode_field(&self.timestamp)
            .encode_field(&self.recv_services)
            .encode_field(&self.recv_addr)
            .encode_field(&U16BE(self.recv_port))
            .encode_field(&self.from_services)
            .encode_field(&self.from_addr)
            .encode_field(&U16BE(self.from_port))
            .encode_field(&self.nonce)
            .encode_field(&VarStr(&self.user_agent))
            .encode_field(&self.start_height)
            .encode_field(&self.relay)
            .finish()
    }

    fn decode(payload: &[u8]) -> Result<Self, DecodeError> {
        let dec = Decoder::new(payload);
        let (version,       dec) = dec.decode_field("version")?;
        let (services,      dec) = dec.decode_field("services")?;
        let (timestamp,     dec) = dec.decode_field("timestamp")?;
        let (recv_services, dec) = dec.decode_field("recv_services")?;
        let (recv_addr,     dec) = dec.read_array::<16>("recv_addr")?;
        let (recv_port,     dec) = dec.read_u16_be("recv_port")?;
        let (from_services, dec) = dec.decode_field("from_services")?;
        let (from_addr,     dec) = dec.read_array::<16>("from_addr")?;
        let (from_port,     dec) = dec.read_u16_be("from_port")?;
        let (nonce,         dec) = dec.decode_field("nonce")?;
        let (user_agent,    dec) = dec.read_var_str("user_agent")?;
        let (start_height,  dec) = dec.decode_field("start_height")?;
        // relay is optional — older nodes omit it
        let (relay, _dec) = dec.decode_optional_field::<bool>();
        let relay = relay.unwrap_or(true);

        Ok(Self {
            version, services, timestamp,
            recv_services, recv_addr, recv_port,
            from_services, from_addr, from_port,
            nonce, user_agent, start_height, relay,
        })
    }
}

/// Cheap nonce for self-connection detection.
/// Bitcoin Core: uses GetRand() in src/net.cpp
fn make_nonce() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos() as u64
        | 0xDEAD_BEEF_0000_0000
}