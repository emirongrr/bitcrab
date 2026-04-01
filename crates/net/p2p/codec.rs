//! Bitcoin P2P message framing — 24-byte header encode/decode.
//!
//! Bitcoin Core: CMessageHeader in src/protocol.h

use bitcrab_common::types::hash::hash256;
use super::{
    errors::P2pError,
    message::{Command, Magic, MessageHeader},
};

pub const MAX_MESSAGE_SIZE: u32 = 32 * 1024 * 1024;

/// Compute 4-byte checksum = hash256(payload)[0..4]
///
/// Bitcoin Core: Hash(payload) in src/protocol.cpp
pub fn checksum(payload: &[u8]) -> [u8; 4] {
    let h = hash256(payload);
    [h[0], h[1], h[2], h[3]]
}

/// Encode a 24-byte message header.
///
/// Bitcoin Core: CMessageHeader::Serialize() in src/protocol.cpp
pub fn encode_header(magic: Magic, command: &Command, payload: &[u8]) -> [u8; 24] {
    let mut buf = [0u8; 24];
    buf[0..4].copy_from_slice(&magic.to_bytes());
    buf[4..16].copy_from_slice(&command.to_wire());
    buf[16..20].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    buf[20..24].copy_from_slice(&checksum(payload));
    buf
}

/// Decode a 24-byte message header.
///
/// Bitcoin Core: CMessageHeader::IsValid() in src/protocol.cpp
pub fn decode_header(buf: &[u8; 24], expected_magic: Magic) -> Result<MessageHeader, P2pError> {
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

    let command = Command::from_wire(&buf[4..16].try_into().unwrap());
    let length  = u32::from_le_bytes(buf[16..20].try_into().unwrap());

    if length > MAX_MESSAGE_SIZE {
        return Err(P2pError::MessageTooLarge { size: length, limit: MAX_MESSAGE_SIZE });
    }

    let checksum: [u8; 4] = buf[20..24].try_into().unwrap();
    Ok(MessageHeader { magic, command, length, checksum })
}

/// Verify payload matches header checksum.
pub fn verify_checksum(header: &MessageHeader, payload: &[u8]) -> Result<(), P2pError> {
    let actual = checksum(payload);
    if actual != header.checksum {
        return Err(P2pError::ChecksumMismatch {
            expected: u32::from_be_bytes(header.checksum),
            actual:   u32::from_be_bytes(actual),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let payload = b"hello";
        let encoded = encode_header(Magic::Signet, &Command::Ping, payload);
        let decoded  = decode_header(&encoded, Magic::Signet).unwrap();
        assert_eq!(decoded.command, Command::Ping);
        assert_eq!(decoded.length, 5);
    }

    #[test]
    fn wrong_magic_rejected() {
        let encoded = encode_header(Magic::Mainnet, &Command::Verack, b"");
        assert!(matches!(
            decode_header(&encoded, Magic::Signet),
            Err(P2pError::WrongMagic { .. })
        ));
    }
}