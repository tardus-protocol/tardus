//! In-memory validator state, shared across HTTP request handlers.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

use crate::sign_sessions::SharedSignSessions;
use crate::storage::ValidatorShareRecord;

/// Read-mostly configuration loaded once at boot.
#[derive(Clone, Debug)]
pub struct ValidatorConfig {
    /// Where share records and per-ceremony state live on disk.
    pub data_dir: PathBuf,
    /// HTTP bind address.
    pub bind_addr: std::net::SocketAddr,
    /// Operator-facing name (for logs + transparency log).
    pub operator_name: String,
    /// 32-byte master seed (set if the operator supplied
    /// `--master-seed-hex` or `TARDUS_VALIDATOR_MASTER_SEED`). Held
    /// in process memory for `/admin/reload-share`. `None` disables
    /// share-file decryption (the daemon serves only read-only endpoints).
    pub master_seed: Option<[u8; 32]>,
    /// Token required in the `X-Admin-Token` header for
    /// `/admin/*` endpoints. If `None`, admin endpoints return 403.
    pub admin_token: Option<String>,
    /// Solana JSON-RPC endpoint (e.g. `https://api.mainnet-beta.solana.com`).
    ///
    /// When set, `refresh_round5` will verify that the surrendered coin's
    /// nullifier is present in the on-chain `NullifierSet` PDA before
    /// issuing a partial signature. This closes the state-desynchronisation
    /// window that would otherwise allow a client to reuse the same coin
    /// across multiple off-chain refresh sessions.
    ///
    /// `None` disables the guard (dev / test mode only).
    pub solana_rpc_url: Option<String>,
    /// 32-byte address of the nullifier-tree PDA account.
    ///
    /// Derived from seeds `["tardus", "nullifier-tree"]` and the deployed
    /// program ID via `find_program_address`. Must be set whenever
    /// `solana_rpc_url` is set.
    pub nullifier_tree_pda: Option<[u8; 32]>,
}

/// Shared mutable state. Held inside an `Arc<RwLock<_>>` so it can be
/// cloned cheaply into Axum handlers and concurrently read by readers
/// while writers update it.
#[derive(Debug)]
pub struct ValidatorState {
    /// Loaded share record (None until `load_share` has succeeded).
    pub share: Option<ValidatorShareRecord>,
    /// Counter incremented for every received sign session request.
    pub sign_session_counter: u64,
    /// Counter incremented for every received refresh session request.
    pub refresh_session_counter: u64,
    /// Counter incremented on every successful health probe served.
    pub health_probes_served: u64,
    /// Counter incremented on every successful `/admin/reload-share` call.
    pub share_reloads: u64,
    /// Process start time for the `validator_uptime_seconds` metric.
    pub started_at: Instant,
}

impl Default for ValidatorState {
    fn default() -> Self {
        Self {
            share: None,
            sign_session_counter: 0,
            refresh_session_counter: 0,
            health_probes_served: 0,
            share_reloads: 0,
            started_at: Instant::now(),
        }
    }
}

/// The handle held inside Axum: cheap to clone, shared between threads.
pub type SharedState = Arc<RwLock<ValidatorState>>;

/// Bundled handle passed to Axum handlers: read/write validator state +
/// in-flight sign sessions.
#[derive(Clone)]
pub struct ValidatorHandles {
    pub state: SharedState,
    pub sign_sessions: SharedSignSessions,
}

#[must_use]
pub fn new_shared_state() -> SharedState {
    Arc::new(RwLock::new(ValidatorState::default()))
}
