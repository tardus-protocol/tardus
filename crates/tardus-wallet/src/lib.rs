//! TARDUS user-side wallet SDK.
//!
//! Drives the multi-validator threshold blind sign (issuance) and
//! κ-fold cut-and-choose refresh ceremonies over HTTPS, returning
//! fully verified [`tardus_refresh::coin::Coin`] values to the caller.
//!
//! v3.1 (this iteration): issuance orchestrator + client pool with
//! TLS / mTLS support.
//!
//! v3.2 (next): refresh orchestrator (parallel 6-round flow).
//! v3.3: BIP-39 mnemonic key derivation, multi-keyset support.

pub mod client_pool;
pub mod error;
pub mod issue;
pub mod keysets;
pub mod mnemonic;
pub mod refresh;
pub mod sealed_box;
pub mod wallet_db;

pub use client_pool::{ValidatorEndpoint, WalletClientPool};
pub use error::{Error, Result};
pub use issue::issue_coin;
pub use keysets::{KeysetDb, KeysetInfo, KeysetStore};
pub use mnemonic::{
    derive_master_seed, derive_receiving_keypair, generate_mnemonic, parse_mnemonic, WordCount,
};
pub use refresh::refresh_coin;
pub use wallet_db::WalletDb;
