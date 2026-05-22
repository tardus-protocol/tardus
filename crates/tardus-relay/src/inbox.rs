//! In-memory **or** SQLite-backed inbox keyed by recipient pubkey,
//! with TTL-based pruning.
//!
//! v5.4: backend dispatched internally via [`Backend`] enum so the
//! daemon's `AppState` and the public API stay backend-agnostic.

// SQLite columns hold u128 timestamps cast through i64 — the unix
// epoch in milliseconds fits comfortably in i64 until year 292 277 026.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    // After the v5.4 std::sync::Mutex refactor most methods don't actually
    // await; we keep the async signatures so callers don't break.
    clippy::unused_async
)]

use crate::error::{Error, Result};
use rusqlite::params;
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// A single deposited message. `id` is a server-assigned random hex
/// string; `payload_hex` is opaque (the relay never interprets it).
#[derive(Clone, Debug, Serialize)]
pub struct Message {
    pub id: String,
    pub payload_hex: String,
    pub received_at_unix_ms: u128,
    pub expires_at_unix_ms: u128,
}

#[derive(Debug, Clone)]
struct StoredMessage {
    msg: Message,
    expires_at_inst: Instant,
}

/// Internal backend choice — exposed only via [`InboxStore::in_memory`]
/// and [`InboxStore::sqlite`].
enum Backend {
    Memory(Mutex<HashMap<[u8; 32], Vec<StoredMessage>>>),
    Sqlite(Mutex<rusqlite::Connection>),
}

pub struct InboxStore {
    backend: Backend,
    pub max_per_recipient: usize,
    pub max_payload_bytes: usize,
}

impl InboxStore {
    /// In-memory backend (lost on restart). Default for tests.
    #[must_use]
    pub fn in_memory(max_per_recipient: usize, max_payload_bytes: usize) -> Self {
        Self {
            backend: Backend::Memory(Mutex::new(HashMap::new())),
            max_per_recipient,
            max_payload_bytes,
        }
    }

    /// SQLite-backed persistent inbox. Creates the file + schema if
    /// it doesn't exist. Uses the bundled `SQLite` (no system dep).
    ///
    /// # Errors
    /// I/O or schema-creation failure on the underlying connection.
    pub fn sqlite(
        path: &Path,
        max_per_recipient: usize,
        max_payload_bytes: usize,
    ) -> Result<Self> {
        let conn = rusqlite::Connection::open(path)
            .map_err(|e| Error::BadRecipient(format!("sqlite open: {e}")))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS messages (
                id                   TEXT PRIMARY KEY,
                recipient            BLOB NOT NULL,
                payload_hex          TEXT NOT NULL,
                received_at_unix_ms  INTEGER NOT NULL,
                expires_at_unix_ms   INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_recipient ON messages(recipient);
             CREATE INDEX IF NOT EXISTS idx_expires   ON messages(expires_at_unix_ms);",
        )
        .map_err(|e| Error::BadRecipient(format!("sqlite schema: {e}")))?;
        Ok(Self {
            backend: Backend::Sqlite(Mutex::new(conn)),
            max_per_recipient,
            max_payload_bytes,
        })
    }

    /// Store a new message under `recipient`. Returns the assigned `id`.
    ///
    /// # Errors
    /// - [`Error::PayloadTooLarge`] if `payload_hex` (after hex decode)
    ///   exceeds `max_payload_bytes`.
    /// - [`Error::InboxFull`] if the recipient already has
    ///   `max_per_recipient` messages.
    ///
    /// # Panics
    /// The internal mutex poison would panic, which only happens after
    /// a previous panic inside the lock — never under normal operation.
    pub async fn deposit(
        &self,
        recipient: [u8; 32],
        payload_hex: String,
        ttl: Duration,
    ) -> Result<Message> {
        let approx_bytes = payload_hex.len() / 2;
        if approx_bytes > self.max_payload_bytes {
            return Err(Error::PayloadTooLarge {
                size: approx_bytes,
                max: self.max_payload_bytes,
            });
        }
        let now_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis());
        let now_inst = Instant::now();
        let id = random_id();
        let msg = Message {
            id: id.clone(),
            payload_hex,
            received_at_unix_ms: now_unix_ms,
            expires_at_unix_ms: now_unix_ms + ttl.as_millis(),
        };

        match &self.backend {
            Backend::Memory(m) => {
                let mut map = m.lock().expect("memory mutex");
                let bucket = map.entry(recipient).or_default();
                if bucket.len() >= self.max_per_recipient {
                    return Err(Error::InboxFull {
                        max: self.max_per_recipient,
                    });
                }
                bucket.push(StoredMessage {
                    msg: msg.clone(),
                    expires_at_inst: now_inst + ttl,
                });
            }
            Backend::Sqlite(m) => {
                let conn = m.lock().expect("sqlite mutex");
                let count: usize = conn
                    .query_row(
                        "SELECT COUNT(*) FROM messages WHERE recipient = ? AND expires_at_unix_ms > ?",
                        params![&recipient as &[u8], now_unix_ms as i64],
                        |row| row.get(0),
                    )
                    .map_err(|e| Error::BadRecipient(format!("sqlite count: {e}")))?;
                if count >= self.max_per_recipient {
                    return Err(Error::InboxFull {
                        max: self.max_per_recipient,
                    });
                }
                conn.execute(
                    "INSERT INTO messages (id, recipient, payload_hex, received_at_unix_ms, expires_at_unix_ms) VALUES (?, ?, ?, ?, ?)",
                    params![
                        msg.id,
                        &recipient as &[u8],
                        msg.payload_hex,
                        msg.received_at_unix_ms as i64,
                        msg.expires_at_unix_ms as i64,
                    ],
                )
                .map_err(|e| Error::BadRecipient(format!("sqlite insert: {e}")))?;
            }
        }
        Ok(msg)
    }

    /// List all non-expired messages for `recipient`.
    ///
    /// # Panics
    /// Mutex poison; only reachable after an earlier in-lock panic.
    pub async fn list(&self, recipient: [u8; 32]) -> Vec<Message> {
        let now_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis()) as i64;
        match &self.backend {
            Backend::Memory(m) => {
                let map = m.lock().expect("memory mutex");
                let now_inst = Instant::now();
                map.get(&recipient)
                    .map_or_else(Vec::new, |bucket| {
                        bucket
                            .iter()
                            .filter(|m| m.expires_at_inst > now_inst)
                            .map(|m| m.msg.clone())
                            .collect()
                    })
            }
            Backend::Sqlite(m) => {
                let conn = m.lock().expect("sqlite mutex");
                let Ok(mut stmt) = conn.prepare(
                    "SELECT id, payload_hex, received_at_unix_ms, expires_at_unix_ms
                     FROM messages WHERE recipient = ? AND expires_at_unix_ms > ?",
                ) else {
                    return Vec::new();
                };
                let rows = stmt.query_map(params![&recipient as &[u8], now_unix_ms], |row| {
                    Ok(Message {
                        id: row.get::<_, String>(0)?,
                        payload_hex: row.get::<_, String>(1)?,
                        received_at_unix_ms: row.get::<_, i64>(2)? as u128,
                        expires_at_unix_ms: row.get::<_, i64>(3)? as u128,
                    })
                });
                match rows {
                    Ok(it) => it.filter_map(std::result::Result::ok).collect(),
                    Err(_) => Vec::new(),
                }
            }
        }
    }

    /// Remove a single message by id. Returns whether it existed.
    ///
    /// # Panics
    /// Mutex poison; only reachable after an earlier in-lock panic.
    pub async fn remove(&self, recipient: [u8; 32], id: &str) -> bool {
        match &self.backend {
            Backend::Memory(m) => {
                let mut map = m.lock().expect("memory mutex");
                let Some(bucket) = map.get_mut(&recipient) else {
                    return false;
                };
                let before = bucket.len();
                bucket.retain(|m| m.msg.id != id);
                before != bucket.len()
            }
            Backend::Sqlite(m) => {
                let conn = m.lock().expect("sqlite mutex");
                conn.execute(
                    "DELETE FROM messages WHERE recipient = ? AND id = ?",
                    params![&recipient as &[u8], id],
                )
                .is_ok_and(|n| n > 0)
            }
        }
    }

    /// Drop all expired messages across all recipients. Returns the
    /// total number evicted.
    ///
    /// # Panics
    /// Mutex poison; only reachable after an earlier in-lock panic.
    pub async fn prune(&self) -> usize {
        let now_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis()) as i64;
        match &self.backend {
            Backend::Memory(m) => {
                let now_inst = Instant::now();
                let mut map = m.lock().expect("memory mutex");
                let mut evicted = 0usize;
                map.retain(|_, bucket| {
                    let before = bucket.len();
                    bucket.retain(|m| m.expires_at_inst > now_inst);
                    evicted += before - bucket.len();
                    !bucket.is_empty()
                });
                evicted
            }
            Backend::Sqlite(m) => {
                let conn = m.lock().expect("sqlite mutex");
                conn.execute(
                    "DELETE FROM messages WHERE expires_at_unix_ms <= ?",
                    params![now_unix_ms],
                )
                .unwrap_or(0)
                // (sqlite execute returns affected rows on success.)
            }
        }
    }

    /// Total messages across all recipients (for `/health`).
    ///
    /// # Panics
    /// Mutex poison; only reachable after an earlier in-lock panic.
    pub async fn total_messages(&self) -> usize {
        match &self.backend {
            Backend::Memory(m) => {
                let map = m.lock().expect("memory mutex");
                map.values().map(Vec::len).sum()
            }
            Backend::Sqlite(m) => {
                let conn = m.lock().expect("sqlite mutex");
                conn.query_row("SELECT COUNT(*) FROM messages", [], |row| row.get::<_, i64>(0))
                    .map_or(0, |n| n as usize)
            }
        }
    }

    /// Return whether this is the persistent `SQLite` backend.
    /// Exposed via `/info` for operator visibility.
    #[must_use]
    pub fn is_persistent(&self) -> bool {
        matches!(&self.backend, Backend::Sqlite(_))
    }
}

pub type SharedInbox = Arc<InboxStore>;

#[must_use]
pub fn new_shared_inbox(max_per_recipient: usize, max_payload_bytes: usize) -> SharedInbox {
    Arc::new(InboxStore::in_memory(max_per_recipient, max_payload_bytes))
}

/// Construct a persistent `SQLite`-backed shared inbox.
///
/// # Errors
/// Propagates `SQLite` open / schema failure.
pub fn new_shared_sqlite_inbox(
    path: &Path,
    max_per_recipient: usize,
    max_payload_bytes: usize,
) -> Result<SharedInbox> {
    Ok(Arc::new(InboxStore::sqlite(
        path,
        max_per_recipient,
        max_payload_bytes,
    )?))
}

/// Background task: every `interval`, run `prune`. Spawn from main.
#[allow(clippy::redundant_closure_for_method_calls)]
pub async fn prune_loop(inbox: SharedInbox, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        let evicted = inbox.prune().await;
        if evicted > 0 {
            tracing::debug!(evicted, "pruned expired inbox messages");
        }
    }
}

fn random_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
