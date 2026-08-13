//! Bitcoin P2P wire protocol — message-specific integration tests.

use bitcrab_net::p2p::messages::{
    getdata::GetData,
    inv::{Inv, InvType, InvVector},
    ping::{Ping, Pong},
    verack::Verack,
    version::Version,
    BitcoinMessage,
};

// -----------------------------------------------------------------------
// Version Message Tests
// -----------------------------------------------------------------------

#[test]
fn version_payload_decode_known_vector() {
    let mut payload = Vec::new();
    // version = 70015
    payload.extend_from_slice(&70015i32.to_le_bytes());
    // services = 9 (NODE_NETWORK | NODE_WITNESS)
    payload.extend_from_slice(&9u64.to_le_bytes());
    // timestamp = 1700000000
    payload.extend_from_slice(&1700000000i64.to_le_bytes());
    // recv_services
    payload.extend_from_slice(&0u64.to_le_bytes());
    // recv_addr
    payload.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 127, 0, 0, 1]);
    // recv_port = 8333
    payload.extend_from_slice(&8333u16.to_be_bytes());
    // from_services
    payload.extend_from_slice(&9u64.to_le_bytes());
    // from_addr
    payload.extend_from_slice(&[0u8; 16]);
    // from_port = 0
    payload.extend_from_slice(&0u16.to_be_bytes());
    // nonce
    payload.extend_from_slice(&0xDEADBEEFu64.to_le_bytes());
    // user_agent = "/bitcrab:0.1.0/"
    let ua = b"/bitcrab:0.1.0/";
    payload.push(ua.len() as u8);
    payload.extend_from_slice(ua);
    // start_height = 297000
    payload.extend_from_slice(&297000i32.to_le_bytes());
    // relay = true
    payload.push(1u8);

    let v = Version::decode(&payload).unwrap();
    assert_eq!(v.version, 70015);
    assert_eq!(v.user_agent, "/bitcrab:0.1.0/");
    assert_eq!(v.start_height, 297000);
}

#[test]
fn version_roundtrip() {
    let original = Version::our_version(0, true);
    let encoded = original.encode();
    let decoded = Version::decode(&encoded).unwrap();

    assert_eq!(decoded.version, original.version);
    assert_eq!(decoded.user_agent, original.user_agent);
    assert_eq!(decoded.start_height, original.start_height);
}

// -----------------------------------------------------------------------
// Ping / Pong Tests
// -----------------------------------------------------------------------

#[test]
fn ping_payload_is_8_bytes() {
    let ping = Ping {
        nonce: 0x0102030405060708,
    };
    let encoded = ping.encode();
    assert_eq!(encoded.len(), 8);
    assert_eq!(encoded, [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
}

#[test]
fn pong_echoes_ping_nonce() {
    let nonce = 0xDEAD_BEEF_CAFE_BABEu64;
    let ping = Ping { nonce };
    let encoded = ping.encode();

    let decoded_ping = Ping::decode(&encoded).unwrap();
    assert_eq!(decoded_ping.nonce, nonce);

    let pong = Pong {
        nonce: decoded_ping.nonce,
    };
    let pong_encoded = pong.encode();
    let decoded_pong = Pong::decode(&pong_encoded).unwrap();
    assert_eq!(decoded_pong.nonce, nonce);
}

// -----------------------------------------------------------------------
// Inventory / GetData Tests
// -----------------------------------------------------------------------

#[test]
fn bitcoin_core_inv_type_constants_match_protocol_h() {
    // Bitcoin Core `protocol.h`: enum GetDataMsg.
    assert_eq!(InvType::Error as u32, 0);
    assert_eq!(InvType::Tx as u32, 1);
    assert_eq!(InvType::Block as u32, 2);
    assert_eq!(InvType::FilteredBlock as u32, 3);
    assert_eq!(InvType::CmpctBlock as u32, 4);
    assert_eq!(InvType::Wtx as u32, 5);
    assert_eq!(InvType::WitnessTx as u32, 0x4000_0001);
    assert_eq!(InvType::WitnessBlock as u32, 0x4000_0002);
}

#[test]
fn bitcoin_core_inv_vector_serializes_type_little_endian_then_hash() {
    let inv = Inv {
        inventory: vec![InvVector {
            inv_type: InvType::WitnessBlock,
            hash: [0x11; 32],
        }],
    };

    let encoded = inv.encode();
    assert_eq!(encoded.len(), 37);
    assert_eq!(encoded[0], 1);
    assert_eq!(&encoded[1..5], &0x4000_0002u32.to_le_bytes());
    assert_eq!(&encoded[5..37], &[0x11; 32]);

    let decoded = Inv::decode(&encoded).unwrap();
    assert_eq!(decoded.inventory.len(), 1);
    assert_eq!(decoded.inventory[0].inv_type, InvType::WitnessBlock);
    assert_eq!(decoded.inventory[0].hash, [0x11; 32]);
}

#[test]
fn bitcoin_core_getdata_uses_same_inventory_vector_wire_format() {
    let getdata = GetData {
        inventory: vec![
            InvVector {
                inv_type: InvType::Tx,
                hash: [0x22; 32],
            },
            InvVector {
                inv_type: InvType::Wtx,
                hash: [0x33; 32],
            },
        ],
    };

    let encoded = getdata.encode();
    assert_eq!(encoded[0], 2);
    assert_eq!(&encoded[1..5], &1u32.to_le_bytes());
    assert_eq!(&encoded[37..41], &5u32.to_le_bytes());

    let decoded = GetData::decode(&encoded).unwrap();
    assert_eq!(decoded.inventory.len(), 2);
    assert_eq!(decoded.inventory[0].inv_type, InvType::Tx);
    assert_eq!(decoded.inventory[1].inv_type, InvType::Wtx);
}

// -----------------------------------------------------------------------
// Hardening Tests
// -----------------------------------------------------------------------

#[test]
fn version_too_short_returns_error() {
    let result = Version::decode(&[0u8; 10]);
    assert!(result.is_err());
}

#[test]
fn version_rejects_trailing_bytes() {
    let mut payload = Version::our_version(0, true).encode();
    payload.push(0);
    assert!(Version::decode(&payload).is_err());
}

#[test]
fn verack_rejects_trailing_bytes() {
    assert!(Verack::decode(&[0]).is_err());
}
