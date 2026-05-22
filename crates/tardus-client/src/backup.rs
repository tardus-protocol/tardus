//! Encrypted backup format (spec §6.2).
//!
//! Wraps the wallet's coin store (or any caller-supplied plaintext)
//! in a ChaCha20-Poly1305 AEAD envelope. The key is derived from the
//! user's master seed via HKDF-SHA-512 with a constant info string.
//!
//! Wire format: `nonce_12 || ciphertext_with_tag`.

use alloc::vec::Vec;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand_core::CryptoRngCore;
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

extern crate alloc;

/// HKDF salt for the backup key derivation.
pub const BACKUP_HKDF_SALT: &[u8] = b"TARDUS-wallet-backup-salt-v1";

/// HKDF info string distinguishing the backup-key from other
/// derivations off the same master seed.
pub const BACKUP_HKDF_INFO: &[u8] = b"TARDUS-wallet-backup-v1";

/// Length of the AEAD nonce prefix in the wire format.
pub const NONCE_LEN: usize = 12;

/// Length of the Poly1305 authentication tag suffix in the ciphertext.
pub const TAG_LEN: usize = 16;

/// Derive the 32-byte AEAD key from the master seed.
///
/// # Panics
/// Cannot panic: `Hkdf::expand` with 32-byte output and a 32-byte
/// salt always succeeds.
#[must_use]
pub fn derive_backup_key(master_seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hkdf = Hkdf::<Sha512>::new(Some(BACKUP_HKDF_SALT), master_seed);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(BACKUP_HKDF_INFO, key.as_mut())
        .expect("HKDF-Expand of 32 bytes always succeeds");
    key
}

/// Seal a plaintext into the canonical wire format: `nonce || aead(plaintext)`.
///
/// # Errors
/// - [`Error::AeadFailure`] only on AEAD encryption failure, which is
///   practically unreachable for a ChaCha20-Poly1305 cipher with a
///   well-formed key and nonce; included for defensive completeness.
pub fn seal_backup<R: CryptoRngCore + ?Sized>(
    master_seed: &[u8; 32],
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    let key = derive_backup_key(master_seed);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| Error::AeadFailure)?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a sealed backup.
///
/// # Errors
/// - [`Error::BackupValidationFailed`] if the sealed blob is shorter
///   than `NONCE_LEN + TAG_LEN`, or if AEAD authentication fails
///   (wrong key, tampered ciphertext, or wrong nonce).
pub fn open_backup(master_seed: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::BackupValidationFailed);
    }
    let nonce = Nonce::from_slice(&sealed[..NONCE_LEN]);
    let ciphertext = &sealed[NONCE_LEN..];

    let key = derive_backup_key(master_seed);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| Error::BackupValidationFailed)
}
