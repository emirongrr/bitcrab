pub mod cli;
pub mod initializers;

use std::path::{Path, PathBuf};
use bitcrab_storage::Store;
use bitcrab_net::p2p::message::Magic;
use tracing::info;

pub fn get_client_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("bitcrab=info".parse().unwrap())
                .add_directive("bitcrab_net=info".parse().unwrap())
                .add_directive("bitcrab_rpc=info".parse().unwrap()),
        )
        .init();
}
