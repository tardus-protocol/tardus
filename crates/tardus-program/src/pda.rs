//! PDA seed derivation (spec §5.5).
//!
//! Canonical seed byte sequences for each program-owned account.
//! Returns `Vec<Vec<u8>>` so callers can feed into
//! `solana_program::pubkey::Pubkey::find_program_address` once that
//! dependency is wired in v1.4.2.

use alloc::{vec, vec::Vec};

/// Domain prefix common to all TARDUS PDA seeds.
pub const TARDUS_PREFIX: &[u8] = b"tardus";

/// Seeds for the keyset registry singleton account.
#[must_use]
pub fn keyset_registry_seeds() -> Vec<Vec<u8>> {
    vec![TARDUS_PREFIX.to_vec(), b"keyset-registry".to_vec()]
}

/// Seeds for a vault account holding collateral of `denom`.
#[must_use]
pub fn vault_seeds(denom: u64) -> Vec<Vec<u8>> {
    vec![
        TARDUS_PREFIX.to_vec(),
        b"vault".to_vec(),
        denom.to_le_bytes().to_vec(),
    ]
}

/// Seeds for the nullifier tree account.
#[must_use]
pub fn nullifier_tree_seeds() -> Vec<Vec<u8>> {
    vec![TARDUS_PREFIX.to_vec(), b"nullifier-tree".to_vec()]
}

/// **v1.4.13** — Seeds for the SponsorPool PDA: a program-owned
/// account holding both lamports (community-funded faucet) AND
/// rate-limit accounting state (`last_payout_slot`).
#[must_use]
pub fn sponsor_pool_seeds() -> Vec<Vec<u8>> {
    vec![TARDUS_PREFIX.to_vec(), b"sponsor-pool".to_vec()]
}
