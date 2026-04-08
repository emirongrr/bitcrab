use bitcrab_net::p2p::addr_man::AddrMan;
use bitcrab_net::p2p::message::Magic;
use bitcrab_net::p2p::peer_manager::PeerManager;
use bitcrab_net::p2p::peer_table::PeerTable;
use bitcrab_storage::InMemoryBackend;

use tokio::time::timeout;

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn test_mock_node_strict_drop() {
    let magic = Magic::Mainnet;

    // ── 1. Mock peer (malicious node) ────────────────────────────────────────
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (mut socket, peer_addr) = listener
            .accept()
            .await
            .expect("mock peer: failed to accept connection");

        eprintln!("[mock] accepted connection from {peer_addr}");

        // Send garbage — invalid magic bytes, not a valid Bitcoin message.
        let garbage = [0xFF; 50];
        socket
            .write_all(&garbage)
            .await
            .expect("mock peer: failed to send garbage");

        eprintln!("[mock] sent 50 bytes of garbage (0xFF)");

        // Now wait for bitcrab to drop the connection.
        // Read until EOF — a dropped connection returns 0 bytes read.
        // This is deterministic unlike write (OS buffers writes even on
        // closed connections).
        // Bağlantı kesilmişse read EOF döner
        let mut buf = [0u8; 256];
        let read_result = timeout(Duration::from_secs(2), socket.read(&mut buf)).await;

        match read_result {
            Err(_) => {
                panic!("[mock] FAIL: bitcrab did not drop the connection within 2s");
            }
            Ok(Ok(0)) => {
                eprintln!("[mock] connection dropped by bitcrab (EOF) ✓");
            }
            Ok(Ok(n)) => {
                // Bitcrab version mesajı gönderdi — bu normal Bitcoin davranışı.
                // Şimdi bağlantının sonunda kapandığını doğrula.
                eprintln!(
                    "[mock] received {} bytes from bitcrab (expected: version message)",
                    n
                );

                // İlk 4 byte magic olmalı
                assert_eq!(
                    &buf[..4],
                    &[0xF9, 0xBE, 0xB4, 0xD9],
                    "first 4 bytes should be mainnet magic"
                );

                // Command field "version" olmalı
                let command = std::str::from_utf8(&buf[4..16])
                    .unwrap_or("")
                    .trim_end_matches('\0');
                assert_eq!(
                    command, "version",
                    "expected version message, got: {command}"
                );

                eprintln!("[mock] correctly received version message ✓");

                // Şimdi garbage gönderdikten sonra bitcrab bağlantıyı kesmeli.
                // Read ile EOF bekle.
                let eof_result = timeout(Duration::from_secs(2), socket.read(&mut buf)).await;

                match eof_result {
                    Err(_) => panic!("[mock] FAIL: bitcrab did not close connection after garbage"),
                    Ok(Ok(0)) => eprintln!("[mock] bitcrab closed connection after garbage ✓"),
                    Ok(Ok(n)) => eprintln!("[mock] bitcrab sent {n} more bytes then closed"),
                    Ok(Err(e)) => eprintln!("[mock] connection torn down: {e} ✓"),
                }
            }
            Ok(Err(e)) => {
                eprintln!("[mock] connection torn down with IO error: {e} ✓");
            }
        }
    });

    // ── 2. Bitcrab node attempts handshake with mock ──────────────────────────
    let _storage = Arc::new(InMemoryBackend::open().unwrap());
    let table = PeerTable::new(AddrMan::new());
    let peer_manager = Arc::new(PeerManager::new(magic, table));

    eprintln!("[bitcrab] connecting to mock peer at {local_addr}");

    let connect_result = timeout(
        Duration::from_secs(3),
        peer_manager.connect_addr(local_addr),
    )
    .await;

    match connect_result {
        Err(_elapsed) => {
            panic!(
                "[bitcrab] FAIL: connect_addr timed out — handshake hung instead of failing fast"
            );
        }
        Ok(Ok((_peer, _rx))) => {
            panic!("[bitcrab] FAIL: connect_addr returned Ok — handshake should have failed on garbage input");
        }
        Ok(Err(e)) => {
            eprintln!("[bitcrab] connect_addr correctly returned Err: {e} ✓");
        }
    }

    // ── 3. Propagate any panic from the mock peer task ────────────────────────
    server_task
        .await
        .expect("mock peer task panicked — see output above");

    eprintln!("[test] PASS ✓");
}
