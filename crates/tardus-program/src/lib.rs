//! TARDUS on-chain Solana program (native Rust, Anchor-free).
//!
//! Implements §5 of the TARDUS specification: account model,
//! instruction set, PDA derivation, and security invariants for the
//! Solana program that anchors the off-chain threshold mint.
//!
//! **v1 scope (this iteration):** runtime-agnostic Rust core. The
//! instruction processors are written as pure functions operating on
//! plain Rust types representing account state; this allows full unit
//! testing without the Solana SBF toolchain.
//!
//! **v1.4.2 (next):** wrap the pure-Rust core with a
//! `solana_program::entrypoint!` macro, add Token-2022 CPI for vault
//! operations, and adapt the nullifier set to Light Protocol
//! ZK-Compression.

#![cfg_attr(not(test), no_std)]
#![doc(html_no_source)]
// `solana_program::entrypoint!` macro emits `cfg(target_os = "solana")`
// and other Solana-specific cfg gates; we suppress the host-build
// warnings about them.
#![allow(unexpected_cfgs)]
#![allow(
    clippy::module_name_repetitions,
    clippy::similar_names,
    clippy::doc_markdown
)]

extern crate alloc;

pub mod ed25519_verifier;
pub mod entrypoint;
pub mod error;
pub mod instruction;
pub mod pda;
pub mod processor;
pub mod sbf_processor;
pub mod state;

pub use error::{Error, Result};
pub use instruction::Instruction;
pub use state::{KeysetEntry, KeysetRegistry, KeysetStatus, NullifierSet, Vault};
