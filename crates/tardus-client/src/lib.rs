//! TARDUS off-chain client SDK.
//!
//! Implements §6 of the TARDUS specification: wallet-side data model,
//! encrypted coin storage, invoice URI scheme (`tardus://`), refresh
//! session orchestration with crash-safe persistence, and the
//! encrypted backup/restore format.
//!
//! This crate exposes the protocol surface only; concrete network
//! transport (HTTP to mint, relay polling, Solana RPC) is the caller's
//! responsibility. The SDK is intentionally I/O-free so it can be
//! linked into wasm browser bundles, mobile apps, CLI tools, and
//! server-side wallet daemons without taking opinion on the runtime.

#![doc(html_no_source)]
#![allow(
    clippy::module_name_repetitions,
    clippy::similar_names,
    clippy::doc_markdown
)]

extern crate alloc;

pub mod backup;
pub mod coin_store;
pub mod error;
pub mod invoice;
pub mod issue;

pub use backup::{open_backup, seal_backup, BACKUP_HKDF_INFO, BACKUP_HKDF_SALT};
pub use coin_store::{CoinStatus, CoinStore, StoredCoin};
pub use error::{Error, Result};
pub use invoice::{Invoice, INVOICE_SCHEME};
pub use issue::{issue_finalize, issue_request, IssueSession};
