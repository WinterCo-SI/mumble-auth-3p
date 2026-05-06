use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use eve_mumble_bridge::{config::Config, routes, state::AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let path = config_path();
    let cfg = Config::from_file(&path)
        .with_context(|| format!("loading configuration from {}", path.display()))?;

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_new(&cfg.log_filter)
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let bind: SocketAddr = cfg
        .bind_addr
        .parse()
        .with_context(|| format!("bind_addr={} is not a SocketAddr", cfg.bind_addr))?;

    let state = AppState::new(cfg).await?;
    let app = routes::build_router(state).layer(TraceLayer::new_for_http());

    tracing::info!(%bind, config = %path.display(), "starting eve-mumble-bridge");
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn config_path() -> PathBuf {
    std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("./config.toml"))
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}
