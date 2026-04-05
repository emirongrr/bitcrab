//! Backend storage tests.
//!
//! Tests for InMemoryBackend and other storage backends.

use bitcrab_storage::InMemoryBackend;

#[test]
fn in_memory_backend_open() {
    let backend = InMemoryBackend::open();
    assert!(backend.is_ok());
}

#[test]
fn in_memory_backend_basic_operations() {
    let _backend = InMemoryBackend::open().unwrap();
    // Just verify backend initializes
}

