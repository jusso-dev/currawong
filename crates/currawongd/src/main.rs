//! currawongd: the Currawong gateway daemon. M0 skeleton only.
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "currawongd skeleton started; SMTP listener lands in M1");
}
