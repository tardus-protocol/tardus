//! Persistent wallet database.
//!
//! Holds a [`tardus_client::CoinStore`] (the user's coins) on disk in
//! an AEAD-sealed file. The AEAD key is derived from the user's
//! BIP-39 master seed via [`tardus_client::backup`]'s HKDF-SHA-512 →
//! ChaCha20-Poly1305 pipeline. Atomic write via tmp + rename.
//!
//! Wallet file format (canonical, v3.4):
//!
//! ```text
//! sealed_file = nonce_12 || ChaCha20-Poly1305(plaintext)
//! plaintext   = borsh(CoinStore)
//! ```
//!
//! The wallet master seed never touches disk; the user supplies the
//! BIP-39 mnemonic at each invocation (via `--phrase`) and the seed
//! is derived per-call.

use crate::error::{Error, Result};
use std::path::{Path, PathBuf};
use tardus_client::backup::{open_backup, seal_backup};
use tardus_client::coin_store::CoinStore;
use zeroize::Zeroizing;

/// On-disk wallet handle. The `CoinStore` is held in memory; call
/// [`WalletDb::save`] to persist any mutations.
pub struct WalletDb {
    path: PathBuf,
    store: CoinStore,
}

impl WalletDb {
    /// Open or initialise the wallet file at `path`. If the file
    /// does not exist, returns an empty `CoinStore` (caller can
    /// `save` to materialise it). If it exists, decrypt with
    /// `master_seed` and load.
    ///
    /// # Errors
    /// - [`Error::Client`] on AEAD-decrypt failure (wrong seed,
    ///   tampered file).
    /// - [`Error::Json`] / [`Error::BadLength`] on malformed file.
    pub fn open(path: PathBuf, master_seed: &[u8; 32]) -> Result<Self> {
        if !path.exists() {
            return Ok(Self {
                path,
                store: CoinStore::new(),
            });
        }
        let sealed = std::fs::read(&path).map_err(|e| Error::ValidatorRejected {
            status: 0,
            body: format!("read wallet file: {e}"),
        })?;
        let plaintext = open_backup(master_seed, &sealed)?;
        let store: CoinStore = borsh::from_slice(&plaintext).map_err(|e| {
            Error::ValidatorRejected {
                status: 0,
                body: format!("borsh decode CoinStore: {e}"),
            }
        })?;
        Ok(Self { path, store })
    }

    /// Persist the in-memory `CoinStore` to disk.
    ///
    /// # Errors
    /// - [`Error::Client`] on AEAD-encrypt failure (practically
    ///   unreachable for ChaCha20-Poly1305).
    /// - [`Error::ValidatorRejected`] (re-used variant) on I/O
    ///   failure.
    pub fn save(&self, master_seed: &[u8; 32]) -> Result<()> {
        use rand::rngs::OsRng;
        let plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(
            borsh::to_vec(&self.store).map_err(|e| Error::ValidatorRejected {
                status: 0,
                body: format!("borsh encode CoinStore: {e}"),
            })?,
        );
        let sealed = seal_backup(master_seed, &plaintext, &mut OsRng)?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &sealed).map_err(|e| Error::ValidatorRejected {
            status: 0,
            body: format!("write tmp wallet file: {e}"),
        })?;
        std::fs::rename(&tmp, &self.path).map_err(|e| Error::ValidatorRejected {
            status: 0,
            body: format!("rename tmp → wallet file: {e}"),
        })?;
        Ok(())
    }

    #[must_use]
    pub fn store(&self) -> &CoinStore {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut CoinStore {
        &mut self.store
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use tardus_client::coin_store::{CoinStatus, StoredCoin};
    use tempfile::TempDir;

    fn rand_seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut s);
        s
    }

    fn dummy_coin(seed: u8) -> StoredCoin {
        StoredCoin {
            secret_bytes: [seed; 32],
            pubkey_bytes: [seed.wrapping_add(1); 32],
            signature_bytes: [seed.wrapping_add(2); 64],
            denom: 1_000_000,
            status: CoinStatus::Active,
            label: Some(format!("dummy-{seed}")),
        }
    }

    #[test]
    fn open_missing_returns_empty_store() {
        let tmp = TempDir::new().unwrap();
        let seed = rand_seed();
        let path = tmp.path().join("wallet.bin");
        let w = WalletDb::open(path, &seed).unwrap();
        assert_eq!(w.store().coins.len(), 0);
    }

    #[test]
    fn add_save_reopen_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let seed = rand_seed();
        let path = tmp.path().join("wallet.bin");

        let mut w = WalletDb::open(path.clone(), &seed).unwrap();
        w.store_mut().add(dummy_coin(1)).unwrap();
        w.store_mut().add(dummy_coin(2)).unwrap();
        w.save(&seed).unwrap();

        let w2 = WalletDb::open(path, &seed).unwrap();
        assert_eq!(w2.store().coins.len(), 2);
        let labels: Vec<_> = w2
            .store()
            .coins
            .iter()
            .filter_map(|c| c.label.as_deref())
            .collect();
        assert!(labels.contains(&"dummy-1"));
        assert!(labels.contains(&"dummy-2"));
        assert_eq!(w2.store().active_balance_for_denom(1_000_000), 2_000_000);
    }

    #[test]
    fn wrong_seed_rejected() {
        let tmp = TempDir::new().unwrap();
        let seed = rand_seed();
        let path = tmp.path().join("wallet.bin");
        let mut w = WalletDb::open(path.clone(), &seed).unwrap();
        w.store_mut().add(dummy_coin(7)).unwrap();
        w.save(&seed).unwrap();

        let mut bad = seed;
        bad[0] ^= 0x01;
        let r = WalletDb::open(path, &bad);
        assert!(r.is_err(), "wrong seed must reject");
    }

    #[test]
    fn tampered_file_rejected() {
        let tmp = TempDir::new().unwrap();
        let seed = rand_seed();
        let path = tmp.path().join("wallet.bin");
        let mut w = WalletDb::open(path.clone(), &seed).unwrap();
        w.store_mut().add(dummy_coin(9)).unwrap();
        w.save(&seed).unwrap();

        let mut blob = std::fs::read(&path).unwrap();
        // Flip a byte past the nonce.
        let i = 16;
        blob[i] ^= 0x01;
        std::fs::write(&path, blob).unwrap();

        let r = WalletDb::open(path, &seed);
        assert!(r.is_err(), "tampered file must reject");
    }
}
