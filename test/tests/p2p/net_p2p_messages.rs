//! Bitcoin P2P wire protocol — message-specific integration tests.

use bitcrab_net::p2p::messages::{version::Version, ping::{Ping, Pong}, BitcoinMessage};

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
    payload.extend_from_slice(&[0,0,0,0, 0,0,0,0, 0,0, 0xFF,0xFF, 127,0,0,1]);
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
    assert_eq!(v.version,      70015);
    assert_eq!(v.user_agent,   "/bitcrab:0.1.0/");
    assert_eq!(v.start_height, 297000);
}

#[test]
fn version_roundtrip() {
    let original = Version::our_version();
    let encoded  = original.encode();
    let decoded  = Version::decode(&encoded).unwrap();

    assert_eq!(decoded.version,      original.version);
    assert_eq!(decoded.user_agent,   original.user_agent);
    assert_eq!(decoded.start_height, original.start_height);
}

// -----------------------------------------------------------------------
// Ping / Pong Tests
// -----------------------------------------------------------------------

#[test]
fn ping_payload_is_8_bytes() {
    let ping = Ping { nonce: 0x0102030405060708 };
    let encoded = ping.encode();
    assert_eq!(encoded.len(), 8);
    assert_eq!(encoded, [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
}

#[test]
fn pong_echoes_ping_nonce() {
    let nonce = 0xDEAD_BEEF_CAFE_BABEu64;
    let ping    = Ping { nonce };
    let encoded = ping.encode();

    let decoded_ping = Ping::decode(&encoded).unwrap();
    assert_eq!(decoded_ping.nonce, nonce);

    let pong    = Pong { nonce: decoded_ping.nonce };
    let pong_encoded = pong.encode();
    let decoded_pong = Pong::decode(&pong_encoded).unwrap();
    assert_eq!(decoded_pong.nonce, nonce);
}

// -----------------------------------------------------------------------
// Hardening Tests
// -----------------------------------------------------------------------

#[test]
fn version_too_short_returns_error() {
    let result = Version::decode(&[0u8; 10]);
    assert!(result.is_err());
}
