//! `ShareStore` trait: abstract over how a validator's share record
//! is loaded into / written from memory.
//!
//! v2.10 ships two implementations:
//!
//!   * [`FileShareStore`] — AEAD-encrypted file backend, the
//!     production default. Wraps the existing
//!     [`crate::storage::read_share_record`] /
//!     [`crate::storage::write_share_record`] pair.
//!
//!   * [`MockShareStore`] — in-memory backend, the test fixture.
//!     Holds the record directly without any encryption — only safe
//!     in unit tests where the process never touches a real
//!     filesystem.
//!
//! v2.11 will add `Pkcs11ShareStore` (HSM-backed). The trait is
//! deliberately small and synchronous-only because share I/O is rare
//! (boot + reshare-finalize only) and the HSM impl will do its own
//! internal blocking.

use crate::error::{Error, Result};
use crate::storage::{
    read_share_record as fs_read, share_path, write_share_record as fs_write,
    ValidatorShareRecord,
};
use std::path::PathBuf;

/// Abstract over share-record persistence.
pub trait ShareStore: Send + Sync {
    /// Load a share record for `keyset_id` if it exists. Returns
    /// `Ok(None)` if no such record (empty backend).
    ///
    /// # Errors
    /// Backend-specific I/O or decryption failure.
    fn load(&self, keyset_id: &[u8; 33]) -> Result<Option<ValidatorShareRecord>>;

    /// Persist a share record, overwriting any previous entry for
    /// the same `keyset_id`.
    ///
    /// # Errors
    /// Backend-specific I/O or encryption failure.
    fn save(&self, record: &ValidatorShareRecord) -> Result<()>;

    /// Enumerate all known share records. Implementations may return
    /// these in any order. Used at boot to populate the in-memory
    /// state and at audit time.
    ///
    /// # Errors
    /// Backend-specific I/O failure.
    fn list(&self) -> Result<Vec<ValidatorShareRecord>>;

    /// Stable identifier of the backend, surfaced in `/info` and the
    /// transparency log. e.g. `"file"`, `"pkcs11"`, `"mock"`.
    fn backend_name(&self) -> &'static str;
}

// =====================================================================
// FileShareStore (production default, v2.1 behavior wrapped)
// =====================================================================

/// File-backed AEAD-encrypted share storage.
///
/// Each share lives in `<data_dir>/share_<hex_keyset_id>.bin`,
/// sealed with ChaCha20-Poly1305 under an HKDF-SHA-512-derived key
/// from the operator's master seed. See [`crate::storage`] for the
/// wire format.
pub struct FileShareStore {
    data_dir: PathBuf,
    master_seed: [u8; 32],
}

impl FileShareStore {
    #[must_use]
    pub fn new(data_dir: PathBuf, master_seed: [u8; 32]) -> Self {
        Self {
            data_dir,
            master_seed,
        }
    }
}

impl ShareStore for FileShareStore {
    fn load(&self, keyset_id: &[u8; 33]) -> Result<Option<ValidatorShareRecord>> {
        let path = share_path(&self.data_dir, keyset_id);
        match fs_read(&path, &self.master_seed) {
            Ok(rec) => Ok(Some(rec)),
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn save(&self, record: &ValidatorShareRecord) -> Result<()> {
        let path = share_path(&self.data_dir, &record.keyset_id);
        fs_write(&path, &self.master_seed, record)
    }

    fn list(&self) -> Result<Vec<ValidatorShareRecord>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.data_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("bin") {
                continue;
            }
            let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            if !name.starts_with("share_") {
                continue;
            }
            match fs_read(&path, &self.master_seed) {
                Ok(rec) => out.push(rec),
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = ?e,
                        "FileShareStore::list skip bad share file"
                    );
                }
            }
        }
        Ok(out)
    }

    fn backend_name(&self) -> &'static str {
        "file"
    }
}

// =====================================================================
// MockShareStore (test fixture only)
// =====================================================================

/// In-memory share store. **NEVER** use in production — the share
/// material lives in plain RAM and is lost on restart.
pub struct MockShareStore {
    inner: std::sync::Mutex<std::collections::HashMap<[u8; 33], ValidatorShareRecord>>,
}

impl Default for MockShareStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MockShareStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Pre-populate with one record. Convenience for tests.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned, which only happens
    /// if a previous mutator panicked — never in practice for this
    /// test-only type.
    #[must_use]
    pub fn with_record(record: ValidatorShareRecord) -> Self {
        let s = Self::new();
        let mut g = s.inner.lock().expect("mock store mutex");
        g.insert(record.keyset_id, record);
        drop(g);
        s
    }
}

impl ShareStore for MockShareStore {
    fn load(&self, keyset_id: &[u8; 33]) -> Result<Option<ValidatorShareRecord>> {
        let g = self.inner.lock().map_err(|_| {
            Error::StorageCorruption("mock store mutex poisoned".to_string())
        })?;
        Ok(g.get(keyset_id).cloned())
    }

    fn save(&self, record: &ValidatorShareRecord) -> Result<()> {
        let mut g = self.inner.lock().map_err(|_| {
            Error::StorageCorruption("mock store mutex poisoned".to_string())
        })?;
        g.insert(record.keyset_id, record.clone());
        Ok(())
    }

    fn list(&self) -> Result<Vec<ValidatorShareRecord>> {
        let g = self.inner.lock().map_err(|_| {
            Error::StorageCorruption("mock store mutex poisoned".to_string())
        })?;
        Ok(g.values().cloned().collect())
    }

    fn backend_name(&self) -> &'static str {
        "mock"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use tempfile::TempDir;

    fn fresh_record(seed: u8) -> ValidatorShareRecord {
        ValidatorShareRecord {
            keyset_id: [seed; 33],
            my_index: u16::from(seed),
            n: 5,
            t: 3,
            epoch: 1,
            joint_pk_bytes: [seed; 32],
            my_share_bytes: [seed.wrapping_add(1); 32],
            qual: vec![1, 2, 3, 4, 5],
        }
    }

    #[test]
    fn file_store_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let store = FileShareStore::new(tmp.path().to_path_buf(), seed);

        // Empty backend → list() returns empty.
        assert!(store.list().unwrap().is_empty());

        let rec = fresh_record(0xAB);
        store.save(&rec).unwrap();

        let loaded = store.load(&rec.keyset_id).unwrap().expect("present");
        assert_eq!(loaded.keyset_id, rec.keyset_id);
        assert_eq!(loaded.my_share_bytes, rec.my_share_bytes);

        let all = store.list().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].keyset_id, rec.keyset_id);

        assert_eq!(store.backend_name(), "file");
    }

    #[test]
    fn file_store_load_missing_returns_none() {
        let tmp = TempDir::new().unwrap();
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let store = FileShareStore::new(tmp.path().to_path_buf(), seed);
        let result = store.load(&[0xCC; 33]).unwrap();
        assert!(result.is_none(), "missing share should be Ok(None)");
    }

    #[test]
    fn mock_store_roundtrip() {
        let store = MockShareStore::new();
        assert_eq!(store.backend_name(), "mock");
        assert!(store.list().unwrap().is_empty());

        let rec = fresh_record(0x77);
        store.save(&rec).unwrap();

        let loaded = store.load(&rec.keyset_id).unwrap().expect("present");
        assert_eq!(loaded.keyset_id, rec.keyset_id);

        let all = store.list().unwrap();
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn mock_with_record_constructor() {
        let rec = fresh_record(0x33);
        let store = MockShareStore::with_record(rec.clone());
        let loaded = store.load(&rec.keyset_id).unwrap().expect("present");
        assert_eq!(loaded.my_index, rec.my_index);
    }

    #[test]
    fn trait_is_object_safe() {
        // Compile-time check: ShareStore must be usable behind Arc<dyn>.
        fn accepts(_: std::sync::Arc<dyn ShareStore>) {}
        let store = std::sync::Arc::new(MockShareStore::new());
        accepts(store);
    }
}
