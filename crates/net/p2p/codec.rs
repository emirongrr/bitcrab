//! Bitcoin P2P message framing — encode and decode the 24-byte header.
//!
//! Bitcoin Core: `CMessageHeader` serialization in src/protocol.cpp
//! and `CNode::ReceiveMsgBytes()` in src/net.cpp
use bitcrab_common::types::hash::hash256;
use super::{
    errors::P2pError,
    message::{Command, Magic, MessageHeader},
};

/// Maximum payload size we accept (32 MB).
pub const MAX_MESSAGE_SIZE: u32 = 32 * 1024 * 1024;

/// Checksum for an empty payload.
/// hash256(b"")[0..4] = [0x5d, 0xf6, 0xe0, 0xe2]
pub const EMPTY_CHECKSUM: [u8; 4] = [0x5d, 0xf6, 0xe0, 0xe2];

/// Compute the 4-byte message checksum.
///
/// checksum = hash256(payload)[0..4]
///
/// Bitcoin Core: `Hash(payload.begin(), payload.end())` in src/protocol.cpp
pub fn checksum(payload: &[u8]) -> [u8; 4] {
    let h = hash256(payload);
    [h[0], h[1], h[2], h[3]]
}

/// Encode a 24-byte message header.
///
/// Bitcoin Core: `CMessageHeader::Serialize()` in src/protocol.cpp
pub fn encode_header(magic: Magic, command: &Command, payload: &[u8]) -> [u8; 24] {
    let mut buf = [0u8; 24];

    // magic — 4 bytes
    buf[0..4].copy_from_slice(&magic.to_bytes());

    // command — 12 bytes, null-padded
    buf[4..16].copy_from_slice(&command.to_wire());

    // length — 4 bytes little-endian
    let len = payload.len() as u32;
    buf[16..20].copy_from_slice(&len.to_le_bytes());

    // checksum — 4 bytes
    buf[20..24].copy_from_slice(&checksum(payload));

    buf
}

/// Decode a 24-byte message header.
///
/// Returns error if magic is wrong or payload size exceeds limit.
///
/// Bitcoin Core: `CMessageHeader::IsValid()` in src/protocol.cpp
pub fn decode_header(
    buf: &[u8; 24],
    expected_magic: Magic,
) -> Result<MessageHeader, P2pError> {
    // magic
    let magic_bytes: [u8; 4] = buf[0..4].try_into().unwrap();
    let magic = Magic::from_bytes(magic_bytes).ok_or(P2pError::WrongMagic {
        expected: u32::from_le_bytes(expected_magic.to_bytes()),
        actual:   u32::from_le_bytes(magic_bytes),
    })?;

    if magic != expected_magic {
        return Err(P2pError::WrongMagic {
            expected: u32::from_le_bytes(expected_magic.to_bytes()),
            actual:   u32::from_le_bytes(magic_bytes),
        });
    }

    // command
    let command_bytes: [u8; 12] = buf[4..16].try_into().unwrap();
    let command = Command::from_wire(&command_bytes);

    // length
    let length = u32::from_le_bytes(buf[16..20].try_into().unwrap());
    if length > MAX_MESSAGE_SIZE {
        return Err(P2pError::MessageTooLarge {
            size:  length,
            limit: MAX_MESSAGE_SIZE,
        });
    }

    // checksum
    let checksum: [u8; 4] = buf[20..24].try_into().unwrap();

    Ok(MessageHeader { magic, command, length, checksum })
}

/// Verify that the payload matches the header checksum.
pub fn verify_checksum(header: &MessageHeader, payload: &[u8]) -> Result<(), P2pError> {
    let actual   = checksum(payload);
    let expected = header.checksum;
    if actual != expected {
        return Err(P2pError::ChecksumMismatch {
            expected: u32::from_be_bytes(expected),
            actual:   u32::from_be_bytes(actual),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_payload_checksum() {
        // hash256(b"") first 4 bytes — known constant
        assert_eq!(checksum(b""), EMPTY_CHECKSUM);
    }

    #[test]
    fn header_roundtrip() {
        let payload = b"hello";
        let encoded = encode_header(Magic::Signet, &Command::Ping, payload);
        let decoded  = decode_header(&encoded, Magic::Signet).unwrap();

        assert_eq!(decoded.magic,   Magic::Signet);
        assert_eq!(decoded.command, Command::Ping);
        assert_eq!(decoded.length,  5);
        assert_eq!(decoded.checksum, checksum(payload));
    }

    #[test]
    fn wrong_magic_rejected() {
        let payload  = b"";
        let encoded  = encode_header(Magic::Mainnet, &Command::Verack, payload);
        let result   = decode_header(&encoded, Magic::Signet);
        assert!(matches!(result, Err(P2pError::WrongMagic { .. })));
    }
}