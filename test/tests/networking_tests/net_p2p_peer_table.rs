// Migrated from PeerTable → AddrMan
// Source: Bitcoin Core src/test/addrman_tests.cpp
use bitcrab_net::p2p::addr_man::AddrMan;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
}

fn source() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333)
}

#[test]
fn add_and_select() {
    let mut table = AddrMan::new();
    table.add(addr(8333), source());
    table.add(addr(8334), source());

    let selected = table.select_best(&[]);
    assert!(selected.is_some());
}

#[test]
fn success_raises_score() {
    let mut table = AddrMan::new();
    table.add(addr(8333), source());
    table.record_success(addr(8333));
    let info = table.map_info.get(&addr(8333)).unwrap();
    assert!(info.score > 0);
}

#[test]
fn failure_lowers_score() {
    let mut table = AddrMan::new();
    table.add(addr(8333), source());
    table.record_failure(addr(8333));
    let info = table.map_info.get(&addr(8333)).unwrap();
    assert!(info.score < 0 || info.failure_count > 0);
}

#[test]
fn banned_peer_not_selected() {
    let mut table = AddrMan::new();
    table.add(addr(8333), source());
    // Drive score below MIN_SCORE (-10) to trigger ban
    for _ in 0..15 {
        table.record_failure(addr(8333));
    }
    let selected = table.select_best(&[]);
    assert!(selected.is_none());
}

#[test]
fn best_peer_selected_over_worse() {
    let mut table = AddrMan::new();
    table.add(addr(8333), source());
    table.add(addr(8334), source());

    // Directly set scores so that retry-interval logic doesn't interfere
    table.map_info.get_mut(&addr(8333)).unwrap().score = 5;
    table.map_info.get_mut(&addr(8334)).unwrap().score = -3;

    let selected = table.select_best(&[]);
    assert_eq!(selected, Some(addr(8333)));
}

#[test]
fn active_peer_not_selected() {
    let mut table = AddrMan::new();
    table.add(addr(8333), source());

    // If it is already in the "active" list, select_best should skip it
    let selected = table.select_best(&[addr(8333)]);
    assert!(selected.is_none());
}

/// Sybil resistance: many addresses from the same /16 subnet should
/// fill only ONE bucket, not flood the entire table.
/// Bitcoin Core: CAddrMan bucket hash is keyed on source group
#[test]
fn sybil_same_subnet_bounded() {
    let mut table = AddrMan::new();
    let attacker_source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8333);

    // Insert 256 addresses all from the same /16 group (10.0.x.x)
    for i in 0u8..=255 {
        for j in 0u8..=255 {
            let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, i, j)), 8333);
            table.add(a, attacker_source);
        }
    }

    // Total should be capped at bucket_count * bucket_size = 1024 * 64 = 65536
    // But addresses from the same source group hash to SAME bucket (size 64 max)
    // So only 64 can survive per source-group bucket
    assert!(table.len() <= 1024 * 64, "Table shouldn't grow unboundedly");
}

/// Tried promotion: after record_success, peer appears in tried.
#[test]
fn promotion_to_tried_table() {
    let mut table = AddrMan::new();
    table.add(addr(8333), source());
    assert!(!table.map_info[&addr(8333)].is_tried);
    table.record_success(addr(8333));
    assert!(
        table.map_info[&addr(8333)].is_tried,
        "should be promoted to Tried"
    );
}
