//! TARDUS core cryptographic primitives.
//!
//! This crate implements the single-party constructions of the TARDUS
//! specification, §2.4 (Schnorr signatures) and §2.5 (Blind Schnorr
//! signatures). Threshold variants from §2.7--§2.9 live in `tardus-mint`
//! and re-use the primitives in this crate.
//!
//! All curve operations target the prime-order subgroup of edwards25519,
//! via `curve25519-dalek`. The hash-to-scalar map `H_{F_l}` is realised
//! by SHA-512 reduced modulo `l`, with a reduction bias bounded by
//! `l / 2^512` (negligible). See spec §2.3 for the rationale.
//!
//! The crate is `no_std`-compatible (alloc required); SecretKey material
//! is zeroised on drop.

#![cfg_attr(not(test), no_std)]
#![doc(html_no_source)]
// Module prefixes (`schnorr_*`, `blind_*`) are intentional at the crate-root
// re-export surface, where the module name is no longer in scope and the
// prefix carries protocol context.
#![allow(
    clippy::module_name_repetitions,
    clippy::similar_names,
    clippy::doc_markdown
)]

extern crate alloc;

pub mod blind;
pub mod error;
pub mod group;
pub mod hash;
pub mod signature;

pub use blind::{
    blind_request, issue_round1, issue_round2, unblind, BlindChallenge, BlindCommit,
    BlindResponse, SignerState, UserState,
};
pub use error::{Error, Result};
pub use group::{Keypair, PublicKey, SecretKey};
pub use signature::{schnorr_sign, schnorr_verify, Signature};
