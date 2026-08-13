use bitcrab_net::p2p::messages::addr::*;
use bitcrab_net::p2p::messages::BitcoinMessage;

#[test]
fn test_addr_encode_decode() {
    let addr = Addr {
        addresses: vec![
            NetAddr {
                time: 1610000000,
                services: 1,
                ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1], // IPv4 localhost mapped
                port: 8333,
            },
        ],
    };

    let encoded = addr.encode();
    let decoded = Addr::decode(&encoded).expect("decode failed");
    assert_eq!(addr, decoded);
}

#[test]
fn test_getaddr_encode_decode() {
    let msg = GetAddr;
    let encoded = msg.encode();
    assert!(encoded.is_empty());
    let decoded = GetAddr::decode(&encoded).expect("decode failed");
    assert_eq!(msg, decoded);
}
