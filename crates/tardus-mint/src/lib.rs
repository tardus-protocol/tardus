//! TARDUS threshold mint.
//!
//! Implements §3 of the TARDUS specification:
//! - Pedersen verifiable secret sharing (§2.6, §3.4.2)
//! - FROST-style distributed key generation (§3.4)
//! - Threshold blind Schnorr signing (§3.6, §2.9)
//! - Proactive secret-sharing rotation (§3.7)
//!
//! The crate is structured around session state machines:
//!
//! - [`dkg::DkgRound1State`], [`dkg::DkgRound2State`], [`dkg::DkgRound3State`]
//!   for the DKG ceremony.
//! - [`sign::SignSession`] for threshold blind signing.
//! - [`rotation::ReshareSession`] for proactive rotation.
//!
//! All session states implement `borsh::BorshSerialize + BorshDeserialize`
//! for caller-side persistence. **Serialization is intended for local
//! trusted persistence only**; deserialization of session state from
//! untrusted sources is outside the trust boundary and MUST NOT be
//! performed without external integrity protection (e.g. an
//! HSM-derived AEAD wrap on the validator daemon).
//!
//! The crate is `no_std`-compatible (alloc required); all secret-bearing
//! state types are zeroised on drop.

#![cfg_attr(not(test), no_std)]
#![doc(html_no_source)]
#![allow(
    clippy::module_name_repetitions,
    clippy::similar_names,
    clippy::doc_markdown
)]

extern crate alloc;

pub mod dkg;
pub mod error;
pub mod rotation;
pub mod sign;
pub mod state;
pub mod transcript;
pub mod vss;

pub use error::{Error, Result};
pub use transcript::{CeremonyId, SessionId, TranscriptSignature};
