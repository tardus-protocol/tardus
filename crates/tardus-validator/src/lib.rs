//! TARDUS validator daemon library.
//!
//! This crate implements the long-running validator process that
//! holds an HSM-mediated share of the joint mint secret and serves
//! the user-facing + inter-operator HTTP API.
//!
//! v2.1 scope: scaffold (state, storage, read-only HTTP endpoints).
//! v2.2 will add the DKG / sign / refresh ceremony coordination
//! endpoints. v2.3 will replace the file-backed share storage with a
//! PKCS#11 HSM backend.

pub mod api;
pub mod dkg_sessions;
pub mod error;
#[cfg(feature = "hsm")]
pub mod pkcs11_store;
pub mod refresh_sessions;
pub mod reshare_sessions;
pub mod share_store;
pub mod sign_sessions;
pub mod state;
pub mod storage;
pub mod transparency_log;

pub use error::{Error, Result};
pub use state::{new_shared_state, SharedState, ValidatorConfig, ValidatorState};
pub use storage::{
    derive_storage_key, read_share_record, share_path, write_share_record, ValidatorShareRecord,
};
