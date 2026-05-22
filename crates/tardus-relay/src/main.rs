use anyhow::{anyhow, Context, Result};
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tardus_relay::{
    api::{router, AppState},
    inbox::{new_shared_inbox, new_shared_sqlite_inbox, prune_loop},
    new_shared_state,
    state::RelayConfig,
};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "tardus-relayd", version, about = "TARDUS encrypted relay daemon")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:9799")]
    bind: SocketAddr,
    #[arg(long, default_value = "anonymous-relay")]
    operator: String,
    #[arg(long, default_value = "256")]
    max_per_recipient: usize,
    #[arg(long, default_value = "65536")]
    max_payload_bytes: usize,
    /// Optional TLS server cert (PEM). Pair with `--tls-key` to enable HTTPS.
    #[arg(long)]
    tls_cert: Option<PathBuf>,
    /// Optional TLS server private key (PEM). Pair with `--tls-cert`.
    #[arg(long)]
    tls_key: Option<PathBuf>,
    /// `SQLite` database file for persistent storage. If omitted, the
    /// relay uses an in-memory inbox (lost on restart).
    #[arg(long)]
    storage_path: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args = Args::parse();

    let config = RelayConfig {
        bind_addr: args.bind,
        operator_name: args.operator,
        max_per_recipient: args.max_per_recipient,
        max_payload_bytes: args.max_payload_bytes,
    };
    let state = new_shared_state();
    let inbox = if let Some(path) = args.storage_path.as_deref() {
        tracing::info!(storage = %path.display(), "SQLite-backed persistent inbox");
        new_shared_sqlite_inbox(path, config.max_per_recipient, config.max_payload_bytes)
            .with_context(|| format!("open sqlite inbox at {}", path.display()))?
    } else {
        tracing::info!("in-memory inbox (volatile)");
        new_shared_inbox(config.max_per_recipient, config.max_payload_bytes)
    };

    tokio::spawn(prune_loop(inbox.clone(), Duration::from_secs(60)));

    let app = AppState {
        config: config.clone(),
        state,
        inbox,
    };

    match (args.tls_cert.as_deref(), args.tls_key.as_deref()) {
        (Some(cert), Some(key)) => {
            tracing::info!(
                operator = %config.operator_name,
                bind = %config.bind_addr,
                max_per_recipient = config.max_per_recipient,
                max_payload_bytes = config.max_payload_bytes,
                tls_cert = %cert.display(),
                "tardus-relayd listening (HTTPS)"
            );
            let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
                .await
                .with_context(|| {
                    format!("load TLS cert={} key={}", cert.display(), key.display())
                })?;
            axum_server::bind_rustls(config.bind_addr, tls_config)
                .serve(router(app).into_make_service())
                .await?;
        }
        (None, None) => {
            let listener = tokio::net::TcpListener::bind(config.bind_addr)
                .await
                .with_context(|| format!("bind {}", config.bind_addr))?;
            tracing::info!(
                operator = %config.operator_name,
                bind = %config.bind_addr,
                max_per_recipient = config.max_per_recipient,
                max_payload_bytes = config.max_payload_bytes,
                "tardus-relayd listening (HTTP)"
            );
            axum::serve(listener, router(app)).await?;
        }
        _ => {
            return Err(anyhow!(
                "both --tls-cert and --tls-key must be supplied (or neither for plain HTTP)"
            ));
        }
    }
    Ok(())
}
