//! Trust-boundary serialisation discipline for mint session state.
//!
//! All `BorshSerialize + BorshDeserialize` impls in this crate are
//! intended **for local trusted persistence only**. The validator
//! daemon is expected to wrap session state in an HSM-derived AEAD
//! before writing to disk, and to verify integrity before
//! deserialisation. Deserialising untrusted bytes into a session state
//! is outside the trust boundary and constitutes a protocol-level bug
//! at the daemon layer.
//!
//! The trust boundary is enforced by convention and documentation
//! rather than by the type system. Phase 4 audit checklist item:
//! verify that every `BorshDeserialize` call-site in the validator
//! daemon source is preceded by an integrity-verifying AEAD open.

#![allow(dead_code)]

// This module is intentionally empty in Phase 1.2b. As Phase 1.2c/d
// adds the concrete state types, this module collects:
//
// - shared serialisation helpers (e.g. canonical field ordering)
// - serialisation-format version constants
// - a single `pub const SERIALISATION_TRUST_NOTE: &str` documenting
//   the trust boundary for downstream tooling/audits
