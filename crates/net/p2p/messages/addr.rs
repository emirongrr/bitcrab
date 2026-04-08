//! Addr and GetAddr messages — Gossip protocol for peer discovery.
//!
//! Bitcoin Core: src/protocol.h
//!

use super::BitcoinMessage;
use crate::p2p::message::Command;
use bitcrab_common::wire::{
    encode::{VarInt, U16BE},
    error::DecodeError,
    Decoder, Encoder,
};

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

/// Network address information shared in an `addr` message.
///
/// Bitcoin Core: CAddress
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetAddr {
    pub time: u32,
    pub services: u64,
    pub ip: [u8; 16],
    pub port: u16, // Stored natively, serialized as BE
}

impl NetAddr {
    pub fn to_socket_addr(&self) -> SocketAddr {
        let ip = IpAddr::V6(Ipv6Addr::from(self.ip));
        // Bitcoin handles mapped addresses. If it's a mapped IPv4,
        // to_canonical() can be used if needed, but SocketAddr handles V6 well.
        SocketAddr::new(ip, self.port)
    }

    pub fn encode(&self, encoder: Encoder) -> Encoder {
        encoder
            .encode_field(&self.time)
            .encode_field(&self.services)
            .encode_field(&self.ip)
            .encode_field(&U16BE(self.port))
    }

    pub fn decode(dec: Decoder<'_>) -> Result<(Self, Decoder<'_>), DecodeError> {
        let (time, d) = dec.decode_field("time")?;
        let (services, d) = d.decode_field("services")?;
        let (ip, d) = d.read_array::<16>("ip")?;
        let (port, d) = d.read_u16_be("port")?;
        Ok((
            Self {
                time,
                services,
                ip,
                port,
            },
            d,
        ))
    }
}

/// The `addr` message.
///
/// Contains a list of known valid peer addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Addr {
    pub addresses: Vec<NetAddr>,
}

impl BitcoinMessage for Addr {
    const COMMAND: Command = Command::Addr;

    fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::new().encode_field(&VarInt(self.addresses.len() as u64));
        for addr in &self.addresses {
            encoder = addr.encode(encoder);
        }
        encoder.finish()
    }

    fn decode(payload: &[u8]) -> Result<Self, DecodeError> {
        let dec = Decoder::new(payload);
        let (count, mut dec) = dec.read_varint("count")?;

        let mut addresses = Vec::with_capacity(count.min(1000) as usize);
        for _ in 0..count {
            let (addr, d) = NetAddr::decode(dec)?;
            addresses.push(addr);
            dec = d;
        }

        Ok(Self { addresses })
    }
}

/// The `getaddr` message.
///
/// Requests an `addr` message from the peer. Payload is always empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetAddr;

impl BitcoinMessage for GetAddr {
    const COMMAND: Command = Command::GetAddr;

    fn encode(&self) -> Vec<u8> {
        Vec::new() // Empty payload
    }

    fn decode(payload: &[u8]) -> Result<Self, DecodeError> {
        if !payload.is_empty() {
            // Some implementations might send a payload, but protocol dictates empty.
            // We ignore trailing bytes generally, but strictly it has no fields.
        }
        Ok(Self)
    }
}
