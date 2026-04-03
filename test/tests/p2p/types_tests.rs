use bitcrab_net::p2p::codec::{decode_header, encode_header, verify_checksum};
use bitcrab_net::p2p::message::{Command, Magic};
use bitcrab_net::p2p::messages::{version::Version, verack::Verack, Message};
use proptest::prelude::*;

/// All valid Magic variants for proptest.
fn any_magic() -> impl Strategy<Value = Magic> {
    prop_oneof![
        Just(Magic::Mainnet),
        Just(Magic::Testnet3),
        Just(Magic::Signet),
        Just(Magic::Regtest),
    ]
}

proptest! {
    /// 1. Encoding/decoding a header round-trips correctly.
    #[test]
    fn test_header_roundtrip(
        magic in any_magic(),
        cmd_variant in 0usize..16usize,
        payload in prop::collection::vec(any::<u8>(), 0..1_000)
    ) {
        // Pick a known Command variant deterministically
        let commands = [
            Command::Version, Command::Verack, Command::Ping, Command::Pong,
            Command::GetHeaders, Command::Headers, Command::GetData, Command::Inv,
            Command::GetBlocks, Command::Block, Command::Tx, Command::Addr,
            Command::GetAddr, Command::SendHeaders, Command::FeeFilter, Command::SendCmpct,
        ];
        let command = commands[cmd_variant % commands.len()].clone();

        let encoded = encode_header(magic, &command, &payload);

        let decoded_result = decode_header(&encoded, magic);
        assert!(decoded_result.is_ok(), "Header should correctly decode something it serialized");

        let decoded = decoded_result.unwrap();
        assert_eq!(decoded.magic, magic);
        assert_eq!(decoded.command, command);
        assert_eq!(decoded.length as usize, payload.len());

        // Checksum should verify correctly
        assert!(verify_checksum(&decoded, &payload).is_ok());
    }

    /// 2. Codec should gracefully reject total garbage bytes (no panic).
    #[test]
    fn test_garbage_decoding(garbage in prop::array::uniform24(any::<u8>())) {
        // We expect either Ok or a proper Error, never a panic
        let _ = decode_header(&garbage, Magic::Mainnet);
    }

    /// 3. Message decoding ignores wrong payload lengths cleanly (no panic).
    #[test]
    fn test_message_garbage_decode(garbage in prop::collection::vec(any::<u8>(), 0..1_000)) {
        let cmd = Command::Version;
        let _ = Message::decode(&cmd, &garbage); // should Error naturally, NO panic
    }
}
