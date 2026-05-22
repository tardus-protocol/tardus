//! Coin store (spec §6.2).
//!
//! In-memory wallet coin collection. Each entry carries a
//! `CoinStatus` marker for spendability tracking. Serialisation via
//! Borsh; encryption-at-rest is the backup layer's responsibility
//! (`backup.rs` in a follow-up iteration).

use alloc::{string::String, vec::Vec};
use borsh::{BorshDeserialize, BorshSerialize};

use crate::error::{Error, Result};

extern crate alloc;

/// Spendability marker for a stored coin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum CoinStatus {
    /// Coin is spendable and has not been used in any in-flight
    /// protocol session.
    Active,

    /// Coin is currently the subject of a pending refresh or withdrawal.
    /// The wallet must not initiate another spend until the in-flight
    /// session resolves or aborts.
    InFlight,

    /// Coin has been spent on-chain (its nullifier is in the
    /// program's nullifier set).
    Spent,
}

/// One coin record in the store.
///
/// Coin secret material is serialised as 32 raw bytes; the field is
/// kept opaque from external callers via the accessor methods.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct StoredCoin {
    /// 32-byte coin secret (`x`).
    pub secret_bytes: [u8; 32],
    /// 32-byte compressed pubkey (`Cp`).
    pub pubkey_bytes: [u8; 32],
    /// 64-byte mint signature on `pubkey_bytes`.
    pub signature_bytes: [u8; 64],
    /// Coin denomination in lamports.
    pub denom: u64,
    /// Status marker.
    pub status: CoinStatus,
    /// Free-form label (e.g. "from invoice 0x42…", optional).
    pub label: Option<String>,
}

impl StoredCoin {
    /// Compute the nullifier of this coin
    /// (`SHA-256("TARDUS-nullifier-v1" || pubkey_bytes)`).
    ///
    /// v1.4.3 revision: bound to the public commitment `Cp`, not the
    /// secret `x`. See `tardus_refresh::Coin::nullifier` for the
    /// SBF-compatibility rationale.
    #[must_use]
    pub fn nullifier(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"TARDUS-nullifier-v1");
        h.update(self.pubkey_bytes);
        let out = h.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&out);
        bytes
    }
}

/// The wallet's coin collection.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CoinStore {
    pub version: u8,
    pub coins: Vec<StoredCoin>,
}

impl CoinStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            version: 1,
            coins: Vec::new(),
        }
    }

    /// Add a coin to the store.
    ///
    /// # Errors
    /// - [`Error::DuplicateCoin`] if a coin with the same nullifier
    ///   already exists (double-receipt or replay).
    pub fn add(&mut self, coin: StoredCoin) -> Result<()> {
        let nullifier = coin.nullifier();
        if self
            .coins
            .iter()
            .any(|c| c.nullifier() == nullifier)
        {
            return Err(Error::DuplicateCoin);
        }
        self.coins.push(coin);
        Ok(())
    }

    /// Mark a coin (looked up by nullifier) as `InFlight`.
    ///
    /// # Errors
    /// - [`Error::CoinNotFound`] if no matching coin exists.
    pub fn mark_in_flight(&mut self, nullifier: &[u8; 32]) -> Result<()> {
        let entry = self
            .coins
            .iter_mut()
            .find(|c| &c.nullifier() == nullifier)
            .ok_or(Error::CoinNotFound)?;
        entry.status = CoinStatus::InFlight;
        Ok(())
    }

    /// Mark a coin as `Spent` after on-chain confirmation.
    ///
    /// # Errors
    /// - [`Error::CoinNotFound`] if no coin in the store has the
    ///   given nullifier.
    pub fn mark_spent(&mut self, nullifier: &[u8; 32]) -> Result<()> {
        let entry = self
            .coins
            .iter_mut()
            .find(|c| &c.nullifier() == nullifier)
            .ok_or(Error::CoinNotFound)?;
        entry.status = CoinStatus::Spent;
        Ok(())
    }

    /// Sum the denominations of all `Active` coins of a given denom.
    #[must_use]
    pub fn active_balance_for_denom(&self, denom: u64) -> u64 {
        self.coins
            .iter()
            .filter(|c| c.denom == denom && c.status == CoinStatus::Active)
            .map(|c| c.denom)
            .sum()
    }

    /// Sum the denominations of all `Active` coins, across denoms.
    #[must_use]
    pub fn total_active_balance(&self) -> u64 {
        self.coins
            .iter()
            .filter(|c| c.status == CoinStatus::Active)
            .map(|c| c.denom)
            .sum()
    }

    /// Find the first `Active` coin of the requested denom.
    #[must_use]
    pub fn find_active(&self, denom: u64) -> Option<&StoredCoin> {
        self.coins
            .iter()
            .find(|c| c.denom == denom && c.status == CoinStatus::Active)
    }
}
