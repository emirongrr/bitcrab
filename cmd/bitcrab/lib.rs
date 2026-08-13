pub mod cli;
pub mod initializers;

pub fn get_client_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("warn")
            .add_directive("bitcrab=info".parse().unwrap())
            .add_directive("bitcrab_net=info".parse().unwrap())
            .add_directive("bitcrab_rpc=info".parse().unwrap())
    });

    tracing_subscriber::fmt().with_env_filter(filter).init();
}
