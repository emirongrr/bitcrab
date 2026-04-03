use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("Storage error: {0}")]
    Custom(String),
    #[error("Key not found")]
    NotFound,
}
