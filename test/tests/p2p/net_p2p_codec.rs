//! Bitcoin P2P message framing — codec and header validation tests.
//!
//! Verified against:
//! - Bitcoin Wiki: https://en.wikipedia.org/wiki/Bitcoin_protocol
//! - Bitcoin Core: src/test/serialize_tests.cpp

use bitcrab_net::p2p::{
    codec::{checksum, decode_header, encode_header, verify_checksum},
    message::{Command, Magic},
    errors::P2pError,
};
use bitcrab_common::constants::MAX_MESSAGE_SIZE;
use proptest::prelude::*;

// -----------------------------------------------------------------------
// Known Vector Tests (Moved from crates/net/p2p/tests.rs)
// -----------------------------------------------------------------------

/// Verack header test vector.
#[test]
fn verack_header_known_vector() {
    let raw = hex::decode(
        "F9BEB4D976657261636B000000000000000000005DF6E0E2"
    ).unwrap();

    let buf: [u8; 24] = raw.try_into().unwrap();
    let header = decode_header(&buf, Magic::Mainnet).unwrap();

    assert_eq!(header.magic, Magic::Mainnet);
    assert_eq!(header.command, Command::Verack);
    assert_eq!(header.length, 0);
    assert_eq!(header.checksum, [0x5D, 0xF6, 0xE0, 0xE2]);
}

/// Empty payload checksum must equal 5DF6E0E2.
#[test]
fn empty_payload_checksum_known_vector() {
    assert_eq!(checksum(b""), [0x5D, 0xF6, 0xE0, 0xE2]);
}

/// Magic bytes for all four networks.
#[test]
fn magic_bytes_known_values() {
    assert_eq!(Magic::Mainnet.to_bytes(),  [0xF9, 0xBE, 0xB4, 0xD9]);
    assert_eq!(Magic::Testnet3.to_bytes(), [0x0B, 0x11, 0x09, 0x07]);
    assert_eq!(Magic::Signet.to_bytes(),   [0x0A, 0x03, 0xCF, 0x40]);
    assert_eq!(Magic::Regtest.to_bytes(),  [0xFA, 0xBF, 0xB5, 0xDA]);
}

/// Command wire encoding — null-padded to 12 bytes.
#[test]
fn command_wire_encoding() {
    // "version" = 76 65 72 73 69 6F 6E + 5 null bytes
    let v = Command::Version.to_wire();
    assert_eq!(&v[..7], b"version");
    assert_eq!(&v[7..], &[0u8; 5]);

    // "verack" = 76 65 72 61 63 6B + 6 null bytes
    let va = Command::Verack.to_wire();
    assert_eq!(&va[..6], b"verack");
    assert_eq!(&va[6..], &[0u8; 6]);
}

// -----------------------------------------------------------------------
// Codec Hardening Tests (NEW)
// -----------------------------------------------------------------------

#[test]
fn rejected_oversized_message() {
    let mut buf = [0u8; 24];
    buf[0..4].copy_from_slice(&Magic::Mainnet.to_bytes());
    // Length: MAX_MESSAGE_SIZE + 1
    buf[16..20].copy_from_slice(&((MAX_MESSAGE_SIZE + 1) as u32).to_le_bytes());
    
    let result = decode_header(&buf, Magic::Mainnet);
    assert!(matches!(result, Err(P2pError::MessageTooLarge { .. })));
}

#[test]
fn rejected_wrong_magic() {
    let mut buf = [0u8; 24];
    buf[0..4].copy_from_slice(&Magic::Mainnet.to_bytes());
    
    // Decoding for Signet should fail
    let result = decode_header(&buf, Magic::Signet);
    assert!(matches!(result, Err(P2pError::WrongMagic { .. })));
}

#[test]
fn rejected_invalid_checksum() {
    let header = bitcrab_net::p2p::message::MessageHeader {
        magic: Magic::Mainnet,
        command: Command::Ping,
        length: 8,
        checksum: [0xDE, 0xAD, 0xBE, 0xEF], // Wrong checksum
    };
    let payload = [0u8; 8];
    
    let result = verify_checksum(&header, &payload);
    assert!(matches!(result, Err(P2pError::ChecksumMismatch { .. })));
}

// -----------------------------------------------------------------------
// Property-based Tests (Moved from types_tests.rs)
// -----------------------------------------------------------------------

fn any_magic() -> impl Strategy<Value = Magic> {
    prop_oneof![
        Just(Magic::Mainnet),
        Just(Magic::Testnet3),
        Just(Magic::Signet),
        Just(Magic::Regtest),
    ]
}

proptest! {
    /// Encoding/decoding a header round-trips correctly.
    #[test]
    fn test_header_roundtrip(
        magic in any_magic(),
        cmd_variant in 0usize..16usize,
        payload in prop::collection::vec(any::<u8>(), 0..1_000)
    ) {
        let commands = [
            Command::Version, Command::Verack, Command::Ping, Command::Pong,
            Command::GetHeaders, Command::Headers, Command::GetData, Command::Inv,
            Command::GetBlocks, Command::Block, Command::Tx, Command::Addr,
            Command::GetAddr, Command::SendHeaders, Command::FeeFilter, Command::SendCmpct,
        ];
        let command = commands[cmd_variant % commands.len()].clone();

        let encoded = encode_header(magic, &command, &payload);
        let decoded = decode_header(&encoded, magic).unwrap();
        
        assert_eq!(decoded.magic, magic);
        assert_eq!(decoded.command, command);
        assert_eq!(decoded.length as usize, payload.len());
        assert!(verify_checksum(&decoded, &payload).is_ok());
    }

    /// Codec should gracefully reject total garbage bytes (no panic).
    #[test]
    fn test_garbage_decoding(garbage in prop::array::uniform24(any::<u8>())) {
        let _ = decode_header(&garbage, Magic::Mainnet);
    }
}
