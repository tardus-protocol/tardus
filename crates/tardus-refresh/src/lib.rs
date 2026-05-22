//! TARDUS refresh protocol.
//!
//! Implements §4 of the TARDUS specification:
//! - Coin model: `(secret, pubkey, mint_signature)` (§4.2)
//! - HKDF-SHA-512 coin secret derivation (§4.4) --- explicitly *not*
//!   BIP32-style, per the Cashu NUT-13 lesson
//! - κ-fold cut-and-choose refresh protocol (§4.5) --- implementation
//!   pending in Phase 1.3c
//!
//! All secret-bearing types are zeroised on drop.

#![cfg_attr(not(test), no_std)]
#![doc(html_no_source)]
#![allow(
    clippy::module_name_repetitions,
    clippy::similar_names,
    clippy::doc_markdown
)]

extern crate alloc;

pub mod coin;
pub mod derivation;
pub mod error;
pub mod refresh;

pub use coin::Coin;
pub use derivation::{derive_coin_secret, COIN_SECRET_INFO, REFRESH_DOMAIN};
pub use error::{Error, Result};
