//! Block file storage tests.
//!
//! Tests for `FlatFilePos`, `BlockFileInfo`, and `BlockFileManager`.
//! These tests verify the flat-file format matches Bitcoin Core exactly.

use bitcrab_common::wire::decode::{BitcoinDecode, Decoder};
use bitcrab_common::wire::encode::Encoder;
use bitcrab_storage::block_file::{BlockFileInfo, BlockFileManager, FlatFilePos, Magic};
use std::fs;
use std::path::PathBuf;

fn test_dir() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);

    // Use project root/target for consistency - normalize path separators
    let cwd = std::env::current_dir().expect("Can't get current directory");
    let base = cwd.join("target").join(format!("bitcrab_test_{}", id));

    let _ = fs::create_dir_all(&base);
    base
}

// ── FlatFilePos Tests ─────────────────────────────────────────────────────────

#[test]
fn flat_file_pos_encode_decode_roundtrip() {
    let pos = FlatFilePos::new(42, 1337);
    let bytes = Encoder::new().encode_field(&pos).finish();
    let (decoded, dec) = FlatFilePos::decode(Decoder::new(&bytes)).unwrap();
    dec.finish("FlatFilePos").unwrap();
    assert_eq!(pos, decoded);
}

#[test]
fn flat_file_pos_file_number_boundary() {
    // Test maximum file number (u32::MAX)
    let pos = FlatFilePos::new(u32::MAX, u32::MAX);
    let bytes = Encoder::new().encode_field(&pos).finish();
    let (decoded, _) = FlatFilePos::decode(Decoder::new(&bytes)).unwrap();
    assert_eq!(decoded.file, u32::MAX);
    assert_eq!(decoded.offset, u32::MAX);
}

#[test]
fn flat_file_pos_serialization_length() {
    let pos = FlatFilePos::new(5, 1000);
    let bytes = Encoder::new().encode_field(&pos).finish();
    // Should be exactly 8 bytes: 4 LE (file) + 4 LE (offset)
    assert_eq!(bytes.len(), 8);
}

// ── BlockFileInfo Tests ───────────────────────────────────────────────────────

#[test]
fn block_file_info_encode_decode_roundtrip() {
    let mut info = BlockFileInfo::default();
    info.update_for_block(100, 1_700_000_000);
    info.update_for_block(101, 1_700_000_010);
    info.size = 4096;
    info.undo_size = 512;

    let bytes = Encoder::new().encode_field(&info).finish();
    assert_eq!(bytes.len(), 36);

    let (decoded, dec) = BlockFileInfo::decode(Decoder::new(&bytes)).unwrap();
    dec.finish("BlockFileInfo").unwrap();

    assert_eq!(decoded.blocks, 2);
    assert_eq!(decoded.height_first, 100);
    assert_eq!(decoded.height_last, 101);
    assert_eq!(decoded.size, 4096);
    assert_eq!(decoded.undo_size, 512);
}

#[test]
fn block_file_info_update_for_block_first_block() {
    let mut info = BlockFileInfo::default();
    assert_eq!(info.blocks, 0);

    info.update_for_block(500, 1_600_000_000);

    assert_eq!(info.blocks, 1);
    assert_eq!(info.height_first, 500);
    assert_eq!(info.height_last, 500);
    assert_eq!(info.time_first, 1_600_000_000);
    assert_eq!(info.time_last, 1_600_000_000);
}

#[test]
fn block_file_info_update_bounds_multiple_blocks() {
    let mut info = BlockFileInfo::default();

    // Add multiple blocks
    info.update_for_block(100, 1_600_000_000);
    info.update_for_block(105, 1_600_001_000);
    info.update_for_block(102, 1_599_999_000); // Out of order height
    info.update_for_block(110, 1_600_002_000); // Out of order time

    assert_eq!(info.blocks, 4);
    assert_eq!(info.height_first, 100); // First added
    assert_eq!(info.height_last, 110); // Max height
    assert_eq!(info.time_first, 1_600_000_000); // First added
    assert_eq!(info.time_last, 1_600_002_000); // Max time
}

#[test]
fn block_file_info_serialization_length() {
    let info = BlockFileInfo::default();
    let bytes = Encoder::new().encode_field(&info).finish();
    // Should be exactly 36 bytes as per Bitcoin Core
    assert_eq!(bytes.len(), 36);
}

// ── BlockFileManager Tests ────────────────────────────────────────────────────

#[test]
fn write_and_read_block_roundtrip() {
    let dir = test_dir();
    let mut mgr = BlockFileManager::new(&dir, Magic::Regtest, 0).unwrap();

    let block = b"fake_block_payload";
    let pos = mgr.write_block(block).unwrap();

    // File is written to blocks/ subdirectory
    let file_path = dir.join("blocks").join("blk00000.dat");
    assert!(
        file_path.exists(),
        "Block file should exist at {:?}",
        file_path
    );

    let back = mgr.read_block(pos).unwrap();
    assert_eq!(back, block);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn write_and_read_multiple_blocks() {
    let dir = test_dir();
    let mut mgr = BlockFileManager::new(&dir, Magic::Regtest, 0).unwrap();

    let blocks = vec![
        b"block_1".to_vec(),
        b"block_2_longer_payload".to_vec(),
        b"block_3".to_vec(),
    ];

    let mut positions = Vec::new();
    for block in &blocks {
        let pos = mgr.write_block(block).unwrap();
        positions.push(pos);
    }

    // Verify all blocks can be read back
    for (i, pos) in positions.iter().enumerate() {
        let read = mgr.read_block(*pos).unwrap();
        assert_eq!(&read, &blocks[i]);
    }

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn write_and_read_undo_roundtrip() {
    let dir = test_dir();
    let mut mgr = BlockFileManager::new(&dir, Magic::Regtest, 0).unwrap();

    mgr.write_block(b"block").unwrap();

    let undo = b"undo_payload";
    let (pos, new_size) = mgr.write_undo(0, undo, 0).unwrap();
    let back = mgr.read_undo(pos).unwrap();

    assert_eq!(back, undo);
    assert_eq!(new_size, 8 + undo.len() as u64); // header + payload
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn write_multiple_undo_records() {
    let dir = test_dir();
    let mut mgr = BlockFileManager::new(&dir, Magic::Regtest, 0).unwrap();

    mgr.write_block(b"block").unwrap();

    let undo_data = vec![
        (b"undo_1".to_vec(), 0u64),
        (b"undo_2_longer".to_vec(), 8 + 6),
        (b"undo_3".to_vec(), 8 + 6 + 8 + 13),
    ];

    let mut positions = Vec::new();
    let mut current_size = 0;

    for (undo, expected_size) in &undo_data {
        assert_eq!(current_size, *expected_size);
        let (pos, new_size) = mgr.write_undo(0, undo, current_size).unwrap();
        positions.push(pos);
        current_size = new_size;
    }

    // Verify all undo records
    for (i, pos) in positions.iter().enumerate() {
        let read = mgr.read_undo(*pos).unwrap();
        assert_eq!(&read, &undo_data[i].0);
    }

    fs::remove_dir_all(&dir).ok();
}
#[test]
fn file_rotates_at_max_size() {
    let dir = test_dir();
    let mut mgr = BlockFileManager::new(&dir, Magic::Regtest, 0).unwrap();

    // Ensure first file exists by writing a small block
    mgr.write_block(b"init")
        .expect("Failed to write init block");

    // Now simulate being near the limit
    mgr.current_size = bitcrab_common::constants::MAX_BLOCK_FILE_SIZE - 10;

    let pos = mgr
        .write_block(&vec![0u8; 100])
        .expect("Failed to write block");
    assert_eq!(pos.file, 1, "should have rotated to file 1");
    // Verify file 1 exists
    let file1 = dir.join("blocks").join("blk00001.dat");
    assert!(file1.exists());

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn current_file_state() {
    let dir = test_dir();
    let mgr = BlockFileManager::new(&dir, Magic::Regtest, 0).unwrap();
    assert_eq!(mgr.current_file(), 0);

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn resume_from_existing_file() {
    let dir = test_dir();

    // Write to file 0
    {
        let mut mgr = BlockFileManager::new(&dir, Magic::Regtest, 0).unwrap();
        mgr.write_block(b"first_block").unwrap();
    }

    // Resume with file 0
    {
        let mut mgr = BlockFileManager::new(&dir, Magic::Regtest, 0).unwrap();
        assert_eq!(mgr.current_file(), 0);
        let pos = mgr.write_block(b"second_block").unwrap();
        assert_eq!(pos.file, 0);
    }

    // Resume with file 2 (skip 1)
    {
        let _mgr = BlockFileManager::new(&dir, Magic::Regtest, 2).unwrap();
        assert_eq!(_mgr.current_file(), 2);
    }

    fs::remove_dir_all(&dir).ok();
}

// ── Magic Bytes Tests ─────────────────────────────────────────────────────────

#[test]
fn magic_encode_decode_roundtrip() {
    let magic = Magic::Mainnet;
    let bytes = Encoder::new().encode_field(&magic).finish();
    let (decoded, dec) = Magic::decode(Decoder::new(&bytes)).unwrap();
    dec.finish("Magic").unwrap();
    assert_eq!(magic, decoded);
}

#[test]
fn magic_bytes_all_networks() {
    assert_eq!(Magic::Mainnet.to_bytes(), [0xF9, 0xBE, 0xB4, 0xD9]);
    assert_eq!(Magic::Testnet3.to_bytes(), [0x0B, 0x11, 0x09, 0x07]);
    assert_eq!(Magic::Signet.to_bytes(), [0x0A, 0x03, 0xCF, 0x40]);
    assert_eq!(Magic::Regtest.to_bytes(), [0xFA, 0xBF, 0xB5, 0xDA]);
}

#[test]
fn magic_different_networks_preserved() {
    let networks = vec![
        Magic::Mainnet,
        Magic::Testnet3,
        Magic::Signet,
        Magic::Regtest,
    ];

    for magic in networks {
        let bytes = Encoder::new().encode_field(&magic).finish();
        let (decoded, _) = Magic::decode(Decoder::new(&bytes)).unwrap();
        assert_eq!(magic, decoded);
    }
}

// ── Edge Case Tests ───────────────────────────────────────────────────────────

#[test]
fn empty_block_write_and_read() {
    let dir = test_dir();
    let mut mgr = BlockFileManager::new(&dir, Magic::Regtest, 0).unwrap();

    let empty = b"";
    let pos = mgr.write_block(empty).unwrap();
    let back = mgr.read_block(pos).unwrap();

    assert_eq!(back.len(), 0);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn large_block_write_and_read() {
    let dir = test_dir();
    let mut mgr = BlockFileManager::new(&dir, Magic::Regtest, 0).unwrap();

    let large_block = vec![0xAB; 1024 * 1024]; // 1 MiB
    let pos = mgr.write_block(&large_block).unwrap();
    let back = mgr.read_block(pos).unwrap();

    assert_eq!(back, large_block);
    assert_eq!(back.len(), 1024 * 1024);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn different_magic_bytes_cross_network() {
    let dir = test_dir();

    // Write with MAINNET magic
    {
        let mut mgr = BlockFileManager::new(&dir, Magic::Mainnet, 0).unwrap();
        mgr.write_block(b"mainnet_block").unwrap();
    }

    // Read with same magic should work
    {
        let mgr = BlockFileManager::new(&dir, Magic::Mainnet, 0).unwrap();
        let pos = FlatFilePos::new(0, 8); // Skip header
        let block = mgr.read_block(pos).unwrap();
        assert_eq!(&block, b"mainnet_block");
    }

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn flush_operations() {
    let dir = test_dir();
    let mut mgr = BlockFileManager::new(&dir, Magic::Regtest, 0).unwrap();

    mgr.write_block(b"test_block").unwrap();

    // Flush should not error
    assert!(mgr.flush().is_ok());

    fs::remove_dir_all(&dir).ok();
}
