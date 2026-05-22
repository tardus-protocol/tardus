//! Per-validator DKG ceremony session state.
//!
//! A `DkgSession` holds this validator's `DkgRound1Output` (private
//! state + broadcast + the `n` shares it dealt) plus the
//! `PeerContribution`s it has received from peers. When `n - 1`
//! contributions are present, the session is ready to be finalised
//! via `dkg_finalize`, producing a `DkgFinalised` whose `my_share`
//! becomes the new keyset share.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tardus_mint::dkg::{DkgRound1Output, PeerContribution};
use tardus_mint::transcript::CeremonyId;
use tokio::sync::Mutex;

/// Default TTL for an in-flight DKG ceremony. Longer than sign/refresh
/// because operators may need multiple network round-trips and the
/// ceremony is comparatively rare.
pub const DEFAULT_DKG_TTL: Duration = Duration::from_secs(3600);

/// In-flight DKG ceremony state.
pub struct DkgSession {
    pub my_round1: DkgRound1Output,
    pub n: u16,
    /// Received contributions keyed by `from_index`.
    pub peer_contributions: HashMap<u16, PeerContribution>,
    pub created_at: Instant,
}

#[derive(Default)]
pub struct DkgSessions {
    inner: Mutex<HashMap<CeremonyId, DkgSession>>,
}

impl DkgSessions {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// # Errors
    /// `Err(())` if the same `CeremonyId` is already in flight.
    pub async fn start(&self, ceremony_id: CeremonyId, sess: DkgSession) -> Result<(), ()> {
        let mut map = self.inner.lock().await;
        if map.contains_key(&ceremony_id) {
            return Err(());
        }
        map.insert(ceremony_id, sess);
        Ok(())
    }

    /// Store a peer contribution. Returns the total number of
    /// contributions accumulated so far. `Err(())` if no session
    /// exists for this ceremony.
    ///
    /// # Errors
    /// `Err(())` if no session for this ceremony id is in flight.
    pub async fn contribute(
        &self,
        ceremony_id: CeremonyId,
        from_index: u16,
        contribution: PeerContribution,
    ) -> Result<usize, ()> {
        let mut map = self.inner.lock().await;
        let sess = map.get_mut(&ceremony_id).ok_or(())?;
        sess.peer_contributions.insert(from_index, contribution);
        Ok(sess.peer_contributions.len())
    }

    /// Consume the session for finalisation. Returns the
    /// `DkgRound1Output` (private state needed for `dkg_finalize`)
    /// plus the accumulated peer contributions, ordered by index.
    ///
    /// # Errors
    /// `Err(())` if no session or insufficient contributions
    /// (`< n - 1`).
    pub async fn take_finalisable(
        &self,
        ceremony_id: CeremonyId,
    ) -> Result<(DkgRound1Output, Vec<PeerContribution>, u16), ()> {
        let mut map = self.inner.lock().await;
        let sess = map.remove(&ceremony_id).ok_or(())?;
        let required = (sess.n - 1) as usize;
        if sess.peer_contributions.len() < required {
            // Put it back — caller can retry.
            map.insert(ceremony_id, sess);
            return Err(());
        }
        let mut indexed: Vec<(u16, PeerContribution)> =
            sess.peer_contributions.into_iter().collect();
        indexed.sort_by_key(|(i, _)| *i);
        let contributions = indexed.into_iter().map(|(_, c)| c).collect();
        Ok((sess.my_round1, contributions, sess.n))
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
        map.retain(|_, sess| now.duration_since(sess.created_at) < ttl);
        before - map.len()
    }
}

pub type SharedDkgSessions = Arc<DkgSessions>;

#[must_use]
pub fn new_shared_dkg_sessions() -> SharedDkgSessions {
    Arc::new(DkgSessions::new())
}

pub async fn prune_loop(sessions: SharedDkgSessions, interval: Duration, ttl: Duration) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        let evicted = sessions.prune(ttl).await;
        if evicted > 0 {
            tracing::debug!(evicted, "pruned expired DKG sessions");
        }
    }
}
