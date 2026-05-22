//! On-chain account state (spec §5.2).
//!
//! Pure Rust types representing the in-memory layout of TARDUS
//! program accounts. These are serialised via Borsh in real on-chain
//! storage.

use alloc::{collections::BTreeSet, vec::Vec};
use borsh::{BorshDeserialize, BorshSerialize};

/// Status of a registered keyset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum KeysetStatus {
    Active,
    Revoked,
}

/// A single keyset entry in the registry.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct KeysetEntry {
    /// 33-byte versioned keyset identifier (§3.5).
    pub keyset_id: [u8; 33],
    pub denom: u64,
    pub joint_pk: [u8; 32],
    pub epoch: u64,
    pub status: KeysetStatus,
}

/// Maximum number of keyset entries per registry account.
/// Determined by the Solana account size budget (10MB nominal).
pub const KEYSET_REGISTRY_CAPACITY: usize = 256;

/// The keyset registry account (singleton per program deployment).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct KeysetRegistry {
    pub version: u8,
    pub entries: Vec<KeysetEntry>,
}

impl Default for KeysetRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl KeysetRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            version: 1,
            entries: Vec::new(),
        }
    }

    /// Find an active or revoked entry by `keyset_id`.
    #[must_use]
    pub fn find(&self, keyset_id: &[u8; 33]) -> Option<&KeysetEntry> {
        self.entries.iter().find(|e| &e.keyset_id == keyset_id)
    }

    /// Find an entry by denomination (returns the latest-epoch active one if multiple).
    #[must_use]
    pub fn find_active_for_denom(&self, denom: u64) -> Option<&KeysetEntry> {
        self.entries
            .iter()
            .filter(|e| e.denom == denom && e.status == KeysetStatus::Active)
            .max_by_key(|e| e.epoch)
    }

    #[must_use]
    pub fn find_mut(&mut self, keyset_id: &[u8; 33]) -> Option<&mut KeysetEntry> {
        self.entries.iter_mut().find(|e| &e.keyset_id == keyset_id)
    }
}

/// A vault account: collateral held for one denomination.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Vault {
    pub denom: u64,
    pub collateral: u64,
}

impl Vault {
    #[must_use]
    pub fn new(denom: u64) -> Self {
        Self {
            denom,
            collateral: 0,
        }
    }
}

/// In-memory nullifier set (v1).
///
/// In v1.4.2 this is replaced by a Light Protocol compressed Merkle
/// tree adapter. For v1, a `BTreeSet` provides the same logical
/// behaviour (no duplicate insertion) at the cost of linear-in-size
/// storage; the public API is preserved.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct NullifierSet {
    leaves: BTreeSet<[u8; 32]>,
}

impl NullifierSet {
    #[must_use]
    pub fn new() -> Self {
        Self {
            leaves: BTreeSet::new(),
        }
    }

    /// Returns `true` if `n` was inserted, `false` if already present.
    pub fn insert(&mut self, n: [u8; 32]) -> bool {
        self.leaves.insert(n)
    }

    #[must_use]
    pub fn contains(&self, n: &[u8; 32]) -> bool {
        self.leaves.contains(n)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }
}

/// **v1.4.13 / Faz 9.3** — SponsorPool accounting state.
/// The PDA holds both lamports (the actual SOL pool) AND this
/// rate-limit state. `last_payout_slot` is used to enforce a
/// per-slot rate limit on `SponsorPayout` to bound drain attacks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SponsorPool {
    /// Last slot at which a payout was approved. Initialised to 0
    /// at bootstrap.
    pub last_payout_slot: u64,
    /// Lifetime payouts (informational).
    pub total_payouts: u64,
    /// Lifetime deposits (informational).
    pub total_deposits: u64,
}

impl SponsorPool {
    /// Rate-limit constant: minimum slots between successive payouts.
    /// 5 slots ≈ 2.5 s. Caps the steady-state drain rate at
    /// `payout_size_lamports / 2.5 s`.
    pub const MIN_SLOTS_BETWEEN_PAYOUTS: u64 = 5;
}
