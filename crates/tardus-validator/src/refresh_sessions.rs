//! Per-validator refresh session state (κ-fold cut-and-choose).
//!
//! Same shape as `sign_sessions`, but the held state is
//! `ValidatorRefreshState` (κ nonces instead of one). Same TTL prune
//! pattern.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tardus_mint::transcript::SessionId;
use tardus_refresh::refresh::ValidatorRefreshState;
use tokio::sync::Mutex;

pub const DEFAULT_REFRESH_TTL: Duration = Duration::from_secs(300);

/// In-flight refresh session.
pub struct RefreshSessionEntry {
    pub state: ValidatorRefreshState,
    pub created_at: Instant,
}

#[derive(Default)]
pub struct RefreshSessions {
    inner: Mutex<HashMap<SessionId, RefreshSessionEntry>>,
}

impl RefreshSessions {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// # Errors
    /// `Err(())` if the same session id is already in flight
    /// (nonce-reuse rejection across the κ candidates).
    pub async fn insert(&self, entry: RefreshSessionEntry) -> Result<(), ()> {
        let mut map = self.inner.lock().await;
        if map.contains_key(&entry.state.session_id) {
            return Err(());
        }
        map.insert(entry.state.session_id, entry);
        Ok(())
    }

    pub async fn take(&self, id: &SessionId) -> Option<RefreshSessionEntry> {
        let mut map = self.inner.lock().await;
        map.remove(id)
    }

    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.is_empty()
    }

    pub async fn prune(&self, ttl: Duration) -> usize {
        let now = Instant::now();
        let mut map = self.inner.lock().await;
        let before = map.len();
        map.retain(|_, entry| now.duration_since(entry.created_at) < ttl);
        before - map.len()
    }
}

pub type SharedRefreshSessions = Arc<RefreshSessions>;

#[must_use]
pub fn new_shared_refresh_sessions() -> SharedRefreshSessions {
    Arc::new(RefreshSessions::new())
}

/// Background task: every `interval`, prune sessions older than `ttl`.
pub async fn prune_loop(
    sessions: SharedRefreshSessions,
    interval: Duration,
    ttl: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        let evicted = sessions.prune(ttl).await;
        if evicted > 0 {
            tracing::debug!(evicted, "pruned expired refresh sessions");
        }
    }
}
