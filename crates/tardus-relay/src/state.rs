use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

#[derive(Clone, Debug)]
pub struct RelayConfig {
    pub bind_addr: std::net::SocketAddr,
    pub operator_name: String,
    pub max_per_recipient: usize,
    pub max_payload_bytes: usize,
}

#[derive(Debug)]
pub struct RelayState {
    pub started_at: Instant,
    pub deposits_total: u64,
    pub fetches_total: u64,
}

impl Default for RelayState {
    fn default() -> Self {
        Self {
            started_at: Instant::now(),
            deposits_total: 0,
            fetches_total: 0,
        }
    }
}

pub type SharedState = Arc<RwLock<RelayState>>;

#[must_use]
pub fn new_shared_state() -> SharedState {
    Arc::new(RwLock::new(RelayState::default()))
}
