//! File-backed AEAD-encrypted share storage.
//!
//! v2.1 software-only baseline. v2.3 will swap in a PKCS#11 HSM
//! backend that holds the share material outside process memory.
//! Wire format mirrors `tardus-client::backup`: HKDF-SHA-512 derives
//! a 32-byte ChaCha20-Poly1305 key from a master seed (the operator's
//! locally-protected encryption passphrase, derived by KDF off-process
//! at boot time), and the blob layout is `nonce_12 || ciphertext_with_tag`.

use crate::error::{Error, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng as AeadOsRng},
    AeadCore, ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha512;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

const STORAGE_HKDF_SALT: &[u8] = b"TARDUS-validator-storage-v1";
const STORAGE_HKDF_INFO: &[u8] = b"chacha20poly1305-key";
const NONCE_LEN: usize = 12;

/// On-disk format for a validator's persistent state.
///
/// Holds the share material plus enough metadata to identify which
/// keyset / epoch it belongs to. Encrypted at rest; loaded into
/// memory only after the operator supplies the master seed at boot.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct ValidatorShareRecord {
    /// 0x02-prefixed compressed joint public key.
    pub keyset_id: [u8; 33],
    /// This validator's 1-based index.
    pub my_index: u16,
    /// Threshold parameters: total operators and signing threshold.
    pub n: u16,
    pub t: u16,
    /// Current epoch number (incremented on each successful reshare).
    pub epoch: u64,
    /// 32-byte canonical ed25519 joint public key.
    pub joint_pk_bytes: [u8; 32],
    /// 32-byte canonical scalar — this validator's share of the joint secret.
    pub my_share_bytes: [u8; 32],
    /// Indices of the qualified set (the validators whose contributions
    /// are bound into the joint key).
    pub qual: Vec<u16>,
}

impl Default for ValidatorShareRecord {
    fn default() -> Self {
        Self {
            keyset_id: [0u8; 33],
            my_index: 0,
            n: 0,
            t: 0,
            epoch: 0,
            joint_pk_bytes: [0u8; 32],
            my_share_bytes: [0u8; 32],
            qual: Vec::new(),
        }
    }
}

/// Derive the 32-byte AEAD storage key from the operator's master seed.
///
/// # Panics
/// Cannot panic: HKDF-SHA-512 expand to 32 bytes from a 64-byte PRK is
/// well within the algorithm's output bound (`255 * HashLen`).
#[must_use]
pub fn derive_storage_key(master_seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha512>::new(Some(STORAGE_HKDF_SALT), master_seed);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(STORAGE_HKDF_INFO, &mut *out)
        .expect("HKDF expand 32 bytes from 64-byte PRK is infallible");
    out
}

fn aead_from_key(key: &[u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(Key::from_slice(key))
}

/// Encrypt a `ValidatorShareRecord` and write it atomically to `path`.
///
/// Uses a temp file + rename to avoid corrupting an existing record on
/// crash mid-write.
///
/// # Errors
/// - [`Error::Io`] on file system errors.
/// - [`Error::AeadFailure`] only on encryption-cipher failure, which is
///   practically unreachable for a well-formed key + nonce.
pub fn write_share_record(
    path: &Path,
    master_seed: &[u8; 32],
    record: &ValidatorShareRecord,
) -> Result<()> {
    let key = derive_storage_key(master_seed);
    let aead = aead_from_key(&key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut AeadOsRng);

    let plaintext = borsh::to_vec(record).map_err(|e| Error::ShareDecode(e.to_string()))?;
    let ciphertext = aead
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|_| Error::AeadFailure)?;
    let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    sealed.extend_from_slice(nonce.as_slice());
    sealed.extend_from_slice(&ciphertext);

    // Atomic write: tmp file + rename.
    let tmp_path = path.with_extension("tmp");
    std::fs::write(&tmp_path, &sealed)?;
    std::fs::rename(&tmp_path, path)?;

    // Best-effort zeroise of the plaintext buffer.
    let mut zeroed = plaintext;
    zeroed.zeroize();
    Ok(())
}

/// Read and decrypt a previously-written share record from `path`.
///
/// # Errors
/// - [`Error::Io`] on file-system errors (incl.\ file not found).
/// - [`Error::StorageCorruption`] if the blob is shorter than the AEAD
///   header / nonce.
/// - [`Error::AeadFailure`] if the AEAD decryption fails (wrong key,
///   tampered ciphertext).
/// - [`Error::ShareDecode`] if the decrypted plaintext fails Borsh
///   deserialisation.
pub fn read_share_record(
    path: &Path,
    master_seed: &[u8; 32],
) -> Result<ValidatorShareRecord> {
    let sealed = std::fs::read(path)?;
    if sealed.len() < NONCE_LEN + 16 {
        return Err(Error::StorageCorruption(format!(
            "sealed blob shorter than nonce+tag: {} bytes",
            sealed.len()
        )));
    }
    let key = derive_storage_key(master_seed);
    let aead = aead_from_key(&key);
    let nonce = Nonce::from_slice(&sealed[..NONCE_LEN]);
    let plaintext = aead
        .decrypt(nonce, &sealed[NONCE_LEN..])
        .map_err(|_| Error::AeadFailure)?;
    let record = ValidatorShareRecord::try_from_slice(&plaintext)
        .map_err(|e| Error::ShareDecode(e.to_string()))?;
    Ok(record)
}

/// Convenience: resolve the canonical share-file path for a given data dir
/// and keyset id.
#[must_use]
pub fn share_path(data_dir: &Path, keyset_id: &[u8; 33]) -> PathBuf {
    data_dir.join(format!("share_{}.bin", hex::encode(keyset_id)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use tempfile::TempDir;

    fn fresh_record() -> ValidatorShareRecord {
        ValidatorShareRecord {
            keyset_id: [0x02; 33],
            my_index: 3,
            n: 5,
            t: 3,
            epoch: 1,
            joint_pk_bytes: [0xAA; 32],
            my_share_bytes: [0xBB; 32],
            qual: vec![1, 2, 3, 4, 5],
        }
    }

    #[test]
    fn roundtrip() {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let tmp = TempDir::new().unwrap();
        let path = share_path(tmp.path(), &[0x02; 33]);

        let record = fresh_record();
        write_share_record(&path, &seed, &record).unwrap();
        let recovered = read_share_record(&path, &seed).unwrap();

        assert_eq!(record.keyset_id, recovered.keyset_id);
        assert_eq!(record.my_index, recovered.my_index);
        assert_eq!(record.joint_pk_bytes, recovered.joint_pk_bytes);
        assert_eq!(record.my_share_bytes, recovered.my_share_bytes);
        assert_eq!(record.qual, recovered.qual);
    }

    #[test]
    fn wrong_seed_rejected() {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let tmp = TempDir::new().unwrap();
        let path = share_path(tmp.path(), &[0x02; 33]);

        write_share_record(&path, &seed, &fresh_record()).unwrap();

        let mut bad_seed = seed;
        bad_seed[0] ^= 0x01;
        match read_share_record(&path, &bad_seed) {
            Err(Error::AeadFailure) => {}
            other => panic!("expected AeadFailure, got {other:?}"),
        }
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let tmp = TempDir::new().unwrap();
        let path = share_path(tmp.path(), &[0x02; 33]);

        write_share_record(&path, &seed, &fresh_record()).unwrap();
        let mut blob = std::fs::read(&path).unwrap();
        let tamper_idx = NONCE_LEN + 5;
        blob[tamper_idx] ^= 0x01;
        std::fs::write(&path, blob).unwrap();

        match read_share_record(&path, &seed) {
            Err(Error::AeadFailure) => {}
            other => panic!("expected AeadFailure after tamper, got {other:?}"),
        }
    }

    #[test]
    fn short_blob_rejected() {
        let tmp = TempDir::new().unwrap();
        let path = share_path(tmp.path(), &[0x02; 33]);
        std::fs::write(&path, b"too short").unwrap();
        match read_share_record(&path, &[0u8; 32]) {
            Err(Error::StorageCorruption(_)) => {}
            other => panic!("expected StorageCorruption, got {other:?}"),
        }
    }
}
