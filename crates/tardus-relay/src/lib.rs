//! TARDUS encrypted relay daemon.
//!
//! v5.1 (this iteration): TTL-bound coin-blob inbox keyed by recipient
//! public key. Anonymous deposit (sender posts a blob without
//! authenticating), polled by the recipient.
//!
//! Wire model:
//!
//! ```text
//! POST /inbox/{recipient_pk_hex}
//!   body: { "payload_hex": "<bytes>", "ttl_secs": optional u64 }
//!   → 200 { "id": "<uuid-ish hex>", "expires_at_unix_ms": u64 }
//!
//! GET /inbox/{recipient_pk_hex}
//!   → 200 { "messages": [{ "id": "...", "payload_hex": "...", "received_at_unix_ms": u64 }, ...] }
//!
//! DELETE /inbox/{recipient_pk_hex}/{message_id}
//!   → 200 { "removed": bool }
//! ```
//!
//! Privacy: the relay deliberately accepts unauthenticated POSTs
//! (anyone can deposit). GET-side authentication is delegated to
//! the recipient's wallet (which proves possession of the receiving
//! private key in a future v5.2; for v5.1 the inbox URL itself is
//! the only access control — the relay treats `recipient_pk_hex`
//! as opaque bytes).
//!
//! Storage: in-memory `HashMap<RecipientPk, Vec<Message>>` with TTL
//! pruning. Persistent backend (`RocksDB` / `SQLite`) is a v5.3
//! follow-up.

pub mod api;
pub mod error;
pub mod inbox;
pub mod state;

pub use error::{Error, Result};
pub use inbox::{InboxStore, Message};
pub use state::{new_shared_state, RelayConfig, RelayState, SharedState};
