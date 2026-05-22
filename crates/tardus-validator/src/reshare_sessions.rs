//! Per-validator reshare ceremony state.
//!
//! Mirrors `dkg_sessions` but holds `ReshareRound1Output` instead of
//! `DkgRound1Output`. Each validator must have an existing share
//! loaded before starting a reshare.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tardus_mint::rotation::{ReshareRound1Output, ResharePeerContribution};
use tardus_mint::transcript::CeremonyId;
use tokio::sync::Mutex;

pub const DEFAULT_RESHARE_TTL: Duration = Duration::from_secs(3600);

pub struct ReshareSession {
    pub my_round1: ReshareRound1Output,
    pub n: u16,
    pub peer_contributions: HashMap<u16, ResharePeerContribution>,
    pub created_at: Instant,
}

#[derive(Default)]
pub struct ReshareSessions {
    inner: Mutex<HashMap<CeremonyId, ReshareSession>>,
}

impl ReshareSessions {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// # Errors
    /// `Err(())` if the same ceremony id is already in flight.
    pub async fn start(&self, ceremony_id: CeremonyId, sess: ReshareSession) -> Result<(), ()> {
        let mut map = self.inner.lock().await;
        if map.contains_key(&ceremony_id) {
            return Err(());
        }
        map.insert(ceremony_id, sess);
        Ok(())
    }

    /// # Errors
    /// `Err(())` if no session for this ceremony id is in flight.
    pub async fn contribute(
        &self,
        ceremony_id: CeremonyId,
        from_index: u16,
        contribution: ResharePeerContribution,
    ) -> Result<usize, ()> {
        let mut map = self.inner.lock().await;
        let sess = map.get_mut(&ceremony_id).ok_or(())?;
        sess.peer_contributions.insert(from_index, contribution);
        Ok(sess.peer_contributions.len())
    }

    /// # Errors
    /// `Err(())` if no session or insufficient peer contributions.
    pub async fn take_finalisable(
        &self,
        ceremony_id: CeremonyId,
    ) -> Result<(ReshareRound1Output, Vec<ResharePeerContribution>, u16), ()> {
        let mut map = self.inner.lock().await;
        let sess = map.remove(&ceremony_id).ok_or(())?;
        let required = (sess.n - 1) as usize;
        if sess.peer_contributions.len() < required {
            map.insert(ceremony_id, sess);
            return Err(());
        }
        let mut indexed: Vec<(u16, ResharePeerContribution)> =
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

pub type SharedReshareSessions = Arc<ReshareSessions>;

#[must_use]
pub fn new_shared_reshare_sessions() -> SharedReshareSessions {
    Arc::new(ReshareSessions::new())
}

pub async fn prune_loop(sessions: SharedReshareSessions, interval: Duration, ttl: Duration) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        let evicted = sessions.prune(ttl).await;
        if evicted > 0 {
            tracing::debug!(evicted, "pruned expired reshare sessions");
        }
    }
}
