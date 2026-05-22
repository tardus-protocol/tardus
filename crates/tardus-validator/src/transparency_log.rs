//! Append-only hash-chained transparency log (spec §8.5 channel 1).
//!
//! Every ceremony-affecting event is recorded as one JSON line in a
//! file. Each event carries `prev_event_id` so the chain can be
//! reconstructed and verified by any third party with read access to
//! the file. Tampering with any earlier entry breaks the chain at the
//! tampered point and is detectable by `/transparency/verify-chain`.
//!
//! Privacy: we log only public ceremony state — `ceremony_id`,
//! `event_type`, `from_index`, `n`, `t`, `epoch`, joint public key
//! after finalisation. Never share material, never `k_i` nonces,
//! never per-coin secrets.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

/// One transparency-log entry. The `prev_event_id` field chains it to
/// the previous entry; the genesis event uses all-zero bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Hex-encoded 32-byte SHA-256 hash of
    /// `prev_event_id || ts_unix_ms || event_json`.
    pub event_id: String,
    pub prev_event_id: String,
    /// Unix milliseconds.
    pub ts_unix_ms: u128,
    pub event: TransparencyEvent,
}

/// Public ceremony events. Body is JSON-serialised inside `LogEntry`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TransparencyEvent {
    /// Daemon boot: announces the operator name + share metadata
    /// (if any). Serves as the first entry of each session.
    Boot {
        operator: String,
        bind_addr: String,
        share_loaded: bool,
        keyset_id_hex: Option<String>,
        epoch: Option<u64>,
    },
    DkgStart {
        ceremony_id_hex: String,
        my_index: u16,
        n: u16,
        t: u16,
    },
    DkgFinalize {
        ceremony_id_hex: String,
        my_index: u16,
        joint_pk_hex: String,
        qual: Vec<u16>,
    },
    ReshareStart {
        ceremony_id_hex: String,
        my_index: u16,
        n: u16,
        t: u16,
    },
    ReshareFinalize {
        ceremony_id_hex: String,
        my_index: u16,
        new_epoch: u64,
    },
    SignSessionStart {
        session_id_hex: String,
        my_index: u16,
    },
    RefreshSessionStart {
        session_id_hex: String,
        my_index: u16,
        kappa: u8,
    },
    ShareReload {
        keyset_id_hex: String,
        epoch: u64,
    },
}

/// Append-only hash-chained logger. Held inside an
/// `Arc<Mutex<TransparencyLogger>>` so handlers can append
/// concurrently while preserving total ordering.
pub struct TransparencyLogger {
    file: tokio::fs::File,
    path: PathBuf,
    last_event_id: String,
}

impl TransparencyLogger {
    /// Open `path` for append, scanning any existing entries to
    /// recover `last_event_id`. If the file does not exist, the
    /// chain starts at all-zero genesis.
    ///
    /// # Errors
    /// Standard I/O on open / read.
    pub async fn open(path: PathBuf) -> std::io::Result<Self> {
        // First scan to find the last entry, if any.
        let mut last_id = String::from("0000000000000000000000000000000000000000000000000000000000000000");
        if tokio::fs::try_exists(&path).await? {
            let f = tokio::fs::File::open(&path).await?;
            let mut reader = BufReader::new(f);
            let mut buf = String::new();
            loop {
                buf.clear();
                let n = reader.read_line(&mut buf).await?;
                if n == 0 {
                    break;
                }
                let trimmed = buf.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Ok(entry) = serde_json::from_str::<LogEntry>(trimmed) {
                    last_id = entry.event_id;
                }
            }
        }
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await?;
        Ok(Self {
            file,
            path,
            last_event_id: last_id,
        })
    }

    /// Append an event. Computes `event_id` as
    /// `SHA-256(prev_event_id || ts_unix_ms || event_json)` and
    /// writes one line to the log file.
    ///
    /// # Errors
    /// I/O write failure.
    pub async fn append(&mut self, event: TransparencyEvent) -> std::io::Result<String> {
        let ts_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis());
        let event_json = serde_json::to_string(&event)
            .unwrap_or_else(|_| "{\"type\":\"serialise_failure\"}".to_string());
        let mut hasher = Sha256::new();
        hasher.update(hex::decode(&self.last_event_id).unwrap_or_default());
        hasher.update(ts_unix_ms.to_le_bytes());
        hasher.update(event_json.as_bytes());
        let event_id = hex::encode(hasher.finalize());

        let entry = LogEntry {
            event_id: event_id.clone(),
            prev_event_id: self.last_event_id.clone(),
            ts_unix_ms,
            event,
        };
        let mut line = serde_json::to_string(&entry)
            .map_err(|e| std::io::Error::other(format!("serialise log entry: {e}")))?;
        line.push('\n');
        self.file.write_all(line.as_bytes()).await?;
        self.file.flush().await?;
        self.last_event_id.clone_from(&event_id);
        Ok(event_id)
    }

    #[must_use]
    pub fn last_event_id(&self) -> &str {
        &self.last_event_id
    }

    #[must_use]
    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

pub type SharedTransparency = Arc<Mutex<TransparencyLogger>>;

/// Verify the hash chain of a transparency-log file. Returns the
/// number of valid entries and `Ok(())` if the chain is intact, or
/// `Err((idx, reason))` if entry `idx` is the first bad one.
///
/// # Errors
/// File-read I/O or JSON parse errors as `(0, message)`.
pub async fn verify_chain(path: &PathBuf) -> Result<usize, (usize, String)> {
    let f = tokio::fs::File::open(path)
        .await
        .map_err(|e| (0, format!("open: {e}")))?;
    let mut reader = BufReader::new(f);
    let mut buf = String::new();
    let mut expected_prev =
        String::from("0000000000000000000000000000000000000000000000000000000000000000");
    let mut count = 0usize;
    loop {
        buf.clear();
        let n = reader
            .read_line(&mut buf)
            .await
            .map_err(|e| (count, format!("read: {e}")))?;
        if n == 0 {
            break;
        }
        let trimmed = buf.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry: LogEntry = serde_json::from_str(trimmed)
            .map_err(|e| (count, format!("parse: {e}")))?;
        if entry.prev_event_id != expected_prev {
            return Err((count, format!("prev_event_id mismatch at entry {count}")));
        }
        let event_json = serde_json::to_string(&entry.event)
            .map_err(|e| (count, format!("re-serialise: {e}")))?;
        let mut hasher = Sha256::new();
        hasher.update(hex::decode(&entry.prev_event_id).unwrap_or_default());
        hasher.update(entry.ts_unix_ms.to_le_bytes());
        hasher.update(event_json.as_bytes());
        let recomputed = hex::encode(hasher.finalize());
        if recomputed != entry.event_id {
            return Err((count, format!("event_id mismatch at entry {count}")));
        }
        expected_prev = entry.event_id;
        count += 1;
    }
    Ok(count)
}

/// Read all entries from the log file (small N — operator scrape).
///
/// # Errors
/// I/O or JSON parse errors.
pub async fn read_all(path: &PathBuf) -> std::io::Result<Vec<LogEntry>> {
    let f = tokio::fs::File::open(path).await?;
    let mut reader = BufReader::new(f);
    let mut buf = String::new();
    let mut out = Vec::new();
    loop {
        buf.clear();
        let n = reader.read_line(&mut buf).await?;
        if n == 0 {
            break;
        }
        let trimmed = buf.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<LogEntry>(trimmed) {
            out.push(entry);
        }
    }
    Ok(out)
}
