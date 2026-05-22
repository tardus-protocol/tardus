//! TARDUS validator daemon binary.

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tardus_validator::{
    api::{router, AppState},
    dkg_sessions::{
        new_shared_dkg_sessions, prune_loop as dkg_prune_loop, DEFAULT_DKG_TTL,
    },
    new_shared_state,
    refresh_sessions::{
        new_shared_refresh_sessions, prune_loop as refresh_prune_loop, DEFAULT_REFRESH_TTL,
    },
    reshare_sessions::{
        new_shared_reshare_sessions, prune_loop as reshare_prune_loop, DEFAULT_RESHARE_TTL,
    },
    sign_sessions::{
        new_shared_sign_sessions, prune_loop as sign_prune_loop, DEFAULT_SESSION_TTL,
    },
    state::ValidatorConfig,
    storage::read_share_record,
};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "tardus-validator", version, about = "TARDUS validator daemon")]
struct Args {
    /// Bind address for the HTTP API.
    #[arg(long, default_value = "127.0.0.1:9787")]
    bind: SocketAddr,
    /// Persistent data directory (share records, ceremony state).
    #[arg(long, default_value = "./tardus-validator-data")]
    data_dir: PathBuf,
    /// Operator-facing name, surfaced in /info and the transparency log.
    #[arg(long, default_value = "anonymous-operator")]
    operator: String,
    /// Master-seed hex (64 chars). Use the `TARDUS_VALIDATOR_MASTER_SEED`
    /// env var in production; the CLI arg is for testing only.
    #[arg(long, env = "TARDUS_VALIDATOR_MASTER_SEED")]
    master_seed_hex: Option<String>,
    /// Token required in the `X-Admin-Token` header to access
    /// `/admin/*` endpoints. If unset, admin endpoints return 403.
    #[arg(long, env = "TARDUS_VALIDATOR_ADMIN_TOKEN")]
    admin_token: Option<String>,
    /// Path to the append-only transparency log file. If unset, the
    /// `/transparency/*` endpoints return 404 and no events are logged.
    #[arg(long)]
    transparency_log: Option<PathBuf>,
    /// Path to the PEM-encoded TLS server certificate. If both
    /// `--tls-cert` and `--tls-key` are provided, the daemon serves
    /// HTTPS instead of HTTP.
    #[arg(long)]
    tls_cert: Option<PathBuf>,
    /// Path to the PEM-encoded TLS server private key (matches `--tls-cert`).
    #[arg(long)]
    tls_key: Option<PathBuf>,
    /// Path to a PEM file holding the CA cert(s) used to verify
    /// incoming client certificates. If set, the server requires
    /// every client to present a valid certificate (mTLS).
    /// Requires `--tls-cert` + `--tls-key`.
    #[arg(long)]
    mtls_ca_cert: Option<PathBuf>,
    /// Solana JSON-RPC endpoint used to verify on-chain nullifier
    /// finalization before issuing partial signatures in refresh_round5.
    /// Example: `https://api.mainnet-beta.solana.com`
    /// Required in production (together with --nullifier-tree-pda-hex).
    /// If unset, the nullifier guard is disabled (dev/test mode only).
    #[arg(long, env = "TARDUS_VALIDATOR_SOLANA_RPC_URL")]
    solana_rpc_url: Option<String>,
    /// Hex-encoded 32-byte address of the nullifier-tree PDA account.
    /// Derived from seeds ["tardus", "nullifier-tree"] and the deployed
    /// program ID via find_program_address.
    /// Required when --solana-rpc-url is set.
    #[arg(long, env = "TARDUS_VALIDATOR_NULLIFIER_TREE_PDA")]
    nullifier_tree_pda_hex: Option<String>,
}

fn parse_seed(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).context("master_seed_hex not valid hex")?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "master_seed_hex: expected 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    // rustls 0.23 needs an explicit crypto provider before any TLS use.
    // We pick the `ring` backend (lighter than aws-lc-rs); idempotent.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let args = Args::parse();
    std::fs::create_dir_all(&args.data_dir)
        .with_context(|| format!("create data dir {}", args.data_dir.display()))?;

    let master_seed = args
        .master_seed_hex
        .as_deref()
        .map(parse_seed)
        .transpose()?;
    // Parse optional nullifier-tree PDA address.
    let nullifier_tree_pda = args
        .nullifier_tree_pda_hex
        .as_deref()
        .map(|hex_str| -> anyhow::Result<[u8; 32]> {
            let bytes = hex::decode(hex_str).context("nullifier_tree_pda_hex not valid hex")?;
            if bytes.len() != 32 {
                return Err(anyhow!(
                    "nullifier_tree_pda_hex: expected 32 bytes, got {}",
                    bytes.len()
                ));
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            Ok(out)
        })
        .transpose()?;

    // Enforce: if solana_rpc_url is set, nullifier_tree_pda must also be set.
    if args.solana_rpc_url.is_some() && nullifier_tree_pda.is_none() {
        return Err(anyhow!(
            "--nullifier-tree-pda-hex (or TARDUS_VALIDATOR_NULLIFIER_TREE_PDA) \
             must be set when --solana-rpc-url is configured"
        ));
    }

    let config = ValidatorConfig {
        data_dir: args.data_dir.clone(),
        bind_addr: args.bind,
        operator_name: args.operator,
        master_seed,
        admin_token: args.admin_token,
        solana_rpc_url: args.solana_rpc_url,
        nullifier_tree_pda,
    };
    let state = new_shared_state();

    // Optional: if master seed provided, try to load any share files in data_dir.
    if let Some(seed) = master_seed {
        for entry in std::fs::read_dir(&args.data_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("bin")
                && path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| s.starts_with("share_"))
            {
                match read_share_record(&path, &seed) {
                    Ok(record) => {
                        tracing::info!(
                            file = %path.display(),
                            my_index = record.my_index,
                            n = record.n,
                            t = record.t,
                            epoch = record.epoch,
                            "loaded share record"
                        );
                        let mut s = state.write().await;
                        s.share = Some(record);
                    }
                    Err(e) => {
                        tracing::warn!(file = %path.display(), error = ?e, "skip share record");
                    }
                }
            }
        }
    }

    let sign_sessions = new_shared_sign_sessions();
    tokio::spawn(sign_prune_loop(
        sign_sessions.clone(),
        Duration::from_secs(60),
        DEFAULT_SESSION_TTL,
    ));

    let refresh_sessions = new_shared_refresh_sessions();
    tokio::spawn(refresh_prune_loop(
        refresh_sessions.clone(),
        Duration::from_secs(60),
        DEFAULT_REFRESH_TTL,
    ));

    let dkg_sessions = new_shared_dkg_sessions();
    tokio::spawn(dkg_prune_loop(
        dkg_sessions.clone(),
        Duration::from_secs(120),
        DEFAULT_DKG_TTL,
    ));

    let reshare_sessions = new_shared_reshare_sessions();
    tokio::spawn(reshare_prune_loop(
        reshare_sessions.clone(),
        Duration::from_secs(120),
        DEFAULT_RESHARE_TTL,
    ));

    let transparency = if let Some(path) = args.transparency_log.clone() {
        let logger = tardus_validator::transparency_log::TransparencyLogger::open(path).await?;
        let shared = std::sync::Arc::new(tokio::sync::Mutex::new(logger));
        // Record boot event.
        {
            let share_meta = {
                let s = state.read().await;
                s.share.as_ref().map(|r| (hex::encode(r.keyset_id), r.epoch))
            };
            let (keyset_id_hex, epoch) = match share_meta {
                Some((k, e)) => (Some(k), Some(e)),
                None => (None, None),
            };
            let mut g = shared.lock().await;
            let _ = g
                .append(tardus_validator::transparency_log::TransparencyEvent::Boot {
                    operator: config.operator_name.clone(),
                    bind_addr: config.bind_addr.to_string(),
                    share_loaded: keyset_id_hex.is_some(),
                    keyset_id_hex,
                    epoch,
                })
                .await;
        }
        Some(shared)
    } else {
        None
    };

    let app = AppState {
        config: config.clone(),
        state,
        sign_sessions,
        refresh_sessions,
        dkg_sessions,
        reshare_sessions,
        transparency,
    };

    let router = router(app);
    match (args.tls_cert.as_deref(), args.tls_key.as_deref()) {
        (Some(cert_path), Some(key_path)) => {
            let tls_config = if let Some(ca_path) = args.mtls_ca_cert.as_deref() {
                tracing::info!(
                    operator = %config.operator_name,
                    bind = %config.bind_addr,
                    data_dir = %config.data_dir.display(),
                    tls_cert = %cert_path.display(),
                    mtls_ca_cert = %ca_path.display(),
                    "tardus-validator listening (HTTPS + mTLS)"
                );
                build_mtls_config(cert_path, key_path, ca_path)?
            } else {
                tracing::info!(
                    operator = %config.operator_name,
                    bind = %config.bind_addr,
                    data_dir = %config.data_dir.display(),
                    tls_cert = %cert_path.display(),
                    "tardus-validator listening (HTTPS)"
                );
                axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path)
                    .await
                    .with_context(|| {
                        format!(
                            "load TLS cert={} key={}",
                            cert_path.display(),
                            key_path.display()
                        )
                    })?
            };
            axum_server::bind_rustls(config.bind_addr, tls_config)
                .serve(router.into_make_service())
                .await?;
        }
        (None, None) => {
            if args.mtls_ca_cert.is_some() {
                return Err(anyhow!(
                    "--mtls-ca-cert requires --tls-cert + --tls-key"
                ));
            }
            let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
            tracing::info!(
                operator = %config.operator_name,
                bind = %config.bind_addr,
                data_dir = %config.data_dir.display(),
                "tardus-validator listening (HTTP)"
            );
            axum::serve(listener, router).await?;
        }
        _ => {
            return Err(anyhow!(
                "both --tls-cert and --tls-key must be supplied (or neither for plain HTTP)"
            ));
        }
    }
    Ok(())
}

/// Build a rustls `ServerConfig` that requires mTLS client certificates
/// signed by the CA(s) loaded from `ca_path`, plus serves the server
/// certificate chain from `cert_path` with key `key_path`.
fn build_mtls_config(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    ca_path: &std::path::Path,
) -> Result<axum_server::tls_rustls::RustlsConfig> {
    use rustls::server::WebPkiClientVerifier;
    use rustls::{RootCertStore, ServerConfig};
    use rustls_pki_types::PrivateKeyDer;
    use std::sync::Arc;

    // Server cert chain + private key.
    let server_certs_pem = std::fs::read(cert_path)
        .with_context(|| format!("read tls cert {}", cert_path.display()))?;
    let mut reader = std::io::Cursor::new(&server_certs_pem);
    let server_chain: Vec<rustls_pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .with_context(|| format!("parse PEM certs in {}", cert_path.display()))?;
    if server_chain.is_empty() {
        return Err(anyhow!("no certificates found in {}", cert_path.display()));
    }

    let server_key_pem = std::fs::read(key_path)
        .with_context(|| format!("read tls key {}", key_path.display()))?;
    let mut key_reader = std::io::Cursor::new(&server_key_pem);
    let server_key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut key_reader)
            .with_context(|| format!("parse PEM key in {}", key_path.display()))?
            .ok_or_else(|| anyhow!("no private key found in {}", key_path.display()))?;

    // Trusted CA(s) for client cert verification.
    let ca_pem = std::fs::read(ca_path)
        .with_context(|| format!("read mTLS CA {}", ca_path.display()))?;
    let mut ca_reader = std::io::Cursor::new(&ca_pem);
    let ca_certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut ca_reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .with_context(|| format!("parse PEM CA in {}", ca_path.display()))?;
    if ca_certs.is_empty() {
        return Err(anyhow!("no CA certificates found in {}", ca_path.display()));
    }
    let mut roots = RootCertStore::empty();
    for ca in ca_certs {
        roots
            .add(ca)
            .map_err(|e| anyhow!("add CA to root store: {e}"))?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| anyhow!("build client cert verifier: {e}"))?;

    let server_config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_chain, server_key)
        .map_err(|e| anyhow!("build rustls ServerConfig: {e}"))?;

    Ok(axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(
        server_config,
    )))
}
