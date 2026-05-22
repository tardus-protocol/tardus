//! Per-validator sign session state.
//!
//! Holds the per-session nonce `k_i` (inside `ValidatorR1State`) between
//! Round 1 and Round 3 of the threshold blind sign protocol. Each entry
//! has a creation timestamp; a periodic prune task evicts entries older
//! than the configured TTL to bound memory.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tardus_mint::sign::ValidatorR1State;
use tardus_mint::transcript::SessionId;
use tokio::sync::Mutex;

/// Default TTL for an in-flight sign session — five minutes is the
/// upper bound on the user-facing round-trip latency budget for the
/// blind-sign flow.
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(300);

/// In-flight sign session: holds the Round-1 nonce state (which itself
/// is `ZeroizeOnDrop`, no `Debug`) plus a creation timestamp for TTL.
pub struct SignSessionEntry {
    pub state: ValidatorR1State,
    pub created_at: Instant,
}

#[derive(Default)]
pub struct SignSessions {
    inner: Mutex<HashMap<SessionId, SignSessionEntry>>,
}

impl SignSessions {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a fresh session keyed by its `SessionId`. Returns
    /// `Err(())` if a session with the same id is already in flight
    /// (which would be a nonce-reuse violation if accepted).
    ///
    /// # Errors
    /// `Err(())` if the session id is already in flight — the §3.6
    /// Remark 3.1 nonce-reuse invariant rejection.
    pub async fn insert(&self, entry: SignSessionEntry) -> Result<(), ()> {
        let mut map = self.inner.lock().await;
        if map.contains_key(&entry.state.session_id) {
            return Err(());
        }
        map.insert(entry.state.session_id, entry);
        Ok(())
    }

    /// Remove and return a session by id (consumed in Round 3).
    pub async fn take(&self, id: &SessionId) -> Option<SignSessionEntry> {
        let mut map = self.inner.lock().await;
        map.remove(id)
    }

    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.is_empty()
    }

    /// Drop sessions older than `ttl`. Returns the number evicted.
    pub async fn prune(&self, ttl: Duration) -> usize {
        let now = Instant::now();
        let mut map = self.inner.lock().await;
        let before = map.len();
        map.retain(|_, entry| now.duration_since(entry.created_at) < ttl);
        before - map.len()
    }
}

pub type SharedSignSessions = Arc<SignSessions>;

#[must_use]
pub fn new_shared_sign_sessions() -> SharedSignSessions {
    Arc::new(SignSessions::new())
}

/// Background task: every `interval`, prune sessions older than `ttl`.
/// Spawn with `tokio::spawn(prune_loop(...))` from the daemon main.
pub async fn prune_loop(
    sessions: SharedSignSessions,
    interval: Duration,
    ttl: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        let evicted = sessions.prune(ttl).await;
        if evicted > 0 {
            tracing::debug!(evicted, "pruned expired sign sessions");
        }
    }
}
