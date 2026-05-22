//! Per-keyset wallet metadata: maps a human-readable name (e.g.
//! `"mainnet-1m"`) to the validator URLs + joint public key + denom.
//!
//! Persisted under the same AEAD scheme as the coin store (HKDF-SHA-512
//! derived ChaCha20-Poly1305 from the BIP-39 master seed), in a
//! separate file (default `<data-dir>/keysets.bin`) so the v3.4 wallet
//! file format stays unchanged.

use crate::error::{Error, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tardus_client::backup::{open_backup, seal_backup};
use zeroize::Zeroizing;

/// One keyset's metadata, holding everything `issue` / `refresh` need
/// to reach the mint committee.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct KeysetInfo {
    /// Compressed joint public key (32 bytes, lowercase hex without `0x`).
    pub joint_pk_hex: String,
    /// Per-coin denomination in lamports / token base units.
    pub denom: u64,
    /// Validator base URLs, e.g. `"https://v1.tardus.example.com:9787"`.
    pub validators: Vec<String>,
    /// Optional path to the root CA PEM used to verify validator server certs.
    pub ca_cert_path: Option<String>,
    /// Optional path to the client cert + private key bundle for mTLS.
    pub client_cert_path: Option<String>,
}

/// All registered keysets, keyed by user-chosen name. `BTreeMap` for
/// deterministic on-disk ordering.
#[derive(Default, Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct KeysetStore {
    pub entries: BTreeMap<String, KeysetInfo>,
}

impl KeysetStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or overwrite a keyset.
    pub fn upsert(&mut self, name: impl Into<String>, info: KeysetInfo) {
        self.entries.insert(name.into(), info);
    }

    /// Remove a keyset by name.
    pub fn remove(&mut self, name: &str) -> Option<KeysetInfo> {
        self.entries.remove(name)
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&KeysetInfo> {
        self.entries.get(name)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Persistent handle to the keysets file. Mirrors [`crate::WalletDb`]'s
/// open / save pattern.
pub struct KeysetDb {
    path: PathBuf,
    store: KeysetStore,
}

impl KeysetDb {
    /// Open or initialise the keysets file at `path`. If the file
    /// does not exist, returns an empty store. If it exists,
    /// AEAD-decrypt with `master_seed`.
    ///
    /// # Errors
    /// - [`Error::Client`] on AEAD-decrypt failure (wrong seed,
    ///   tampered file).
    /// - [`Error::ValidatorRejected`] (reused as generic-error) on
    ///   I/O or Borsh decode failure.
    pub fn open(path: PathBuf, master_seed: &[u8; 32]) -> Result<Self> {
        if !path.exists() {
            return Ok(Self {
                path,
                store: KeysetStore::new(),
            });
        }
        let sealed = std::fs::read(&path).map_err(|e| Error::ValidatorRejected {
            status: 0,
            body: format!("read keysets file: {e}"),
        })?;
        let plaintext = open_backup(master_seed, &sealed)?;
        let store: KeysetStore =
            borsh::from_slice(&plaintext).map_err(|e| Error::ValidatorRejected {
                status: 0,
                body: format!("borsh decode KeysetStore: {e}"),
            })?;
        Ok(Self { path, store })
    }

    /// Persist the keyset store to disk.
    ///
    /// # Errors
    /// - [`Error::Client`] on AEAD-encrypt failure.
    /// - [`Error::ValidatorRejected`] on I/O failure.
    pub fn save(&self, master_seed: &[u8; 32]) -> Result<()> {
        use rand::rngs::OsRng;
        let plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(
            borsh::to_vec(&self.store).map_err(|e| Error::ValidatorRejected {
                status: 0,
                body: format!("borsh encode KeysetStore: {e}"),
            })?,
        );
        let sealed = seal_backup(master_seed, &plaintext, &mut OsRng)?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &sealed).map_err(|e| Error::ValidatorRejected {
            status: 0,
            body: format!("write tmp keysets file: {e}"),
        })?;
        std::fs::rename(&tmp, &self.path).map_err(|e| Error::ValidatorRejected {
            status: 0,
            body: format!("rename tmp → keysets file: {e}"),
        })?;
        Ok(())
    }

    #[must_use]
    pub fn store(&self) -> &KeysetStore {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut KeysetStore {
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
    use tempfile::TempDir;

    fn rand_seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut s);
        s
    }

    fn ks_info() -> KeysetInfo {
        KeysetInfo {
            joint_pk_hex: "aa".repeat(32),
            denom: 1_000_000,
            validators: vec![
                "https://v1.example.com".to_string(),
                "https://v2.example.com".to_string(),
                "https://v3.example.com".to_string(),
            ],
            ca_cert_path: Some("/etc/tardus/ca.pem".to_string()),
            client_cert_path: None,
        }
    }

    #[test]
    fn empty_when_missing() {
        let tmp = TempDir::new().unwrap();
        let seed = rand_seed();
        let db = KeysetDb::open(tmp.path().join("ks.bin"), &seed).unwrap();
        assert!(db.store().is_empty());
    }

    #[test]
    fn upsert_save_reopen() {
        let tmp = TempDir::new().unwrap();
        let seed = rand_seed();
        let path = tmp.path().join("ks.bin");

        let mut db = KeysetDb::open(path.clone(), &seed).unwrap();
        db.store_mut().upsert("mainnet-1m", ks_info());
        db.store_mut().upsert(
            "devnet-test",
            KeysetInfo {
                joint_pk_hex: "bb".repeat(32),
                denom: 100_000,
                validators: vec!["http://127.0.0.1:9787".to_string()],
                ca_cert_path: None,
                client_cert_path: None,
            },
        );
        db.save(&seed).unwrap();

        let db2 = KeysetDb::open(path, &seed).unwrap();
        assert_eq!(db2.store().len(), 2);
        let mainnet = db2.store().get("mainnet-1m").unwrap();
        assert_eq!(mainnet.denom, 1_000_000);
        assert_eq!(mainnet.validators.len(), 3);
        assert_eq!(mainnet.ca_cert_path.as_deref(), Some("/etc/tardus/ca.pem"));
    }

    #[test]
    fn remove_returns_old() {
        let tmp = TempDir::new().unwrap();
        let seed = rand_seed();
        let path = tmp.path().join("ks.bin");
        let mut db = KeysetDb::open(path, &seed).unwrap();
        db.store_mut().upsert("k1", ks_info());
        let removed = db.store_mut().remove("k1").unwrap();
        assert_eq!(removed.denom, 1_000_000);
        assert!(db.store_mut().remove("nonexistent").is_none());
    }

    #[test]
    fn wrong_seed_rejected() {
        let tmp = TempDir::new().unwrap();
        let seed = rand_seed();
        let path = tmp.path().join("ks.bin");
        let mut db = KeysetDb::open(path.clone(), &seed).unwrap();
        db.store_mut().upsert("k1", ks_info());
        db.save(&seed).unwrap();

        let mut bad = seed;
        bad[0] ^= 0x01;
        let r = KeysetDb::open(path, &bad);
        assert!(r.is_err(), "wrong seed must reject");
    }
}
