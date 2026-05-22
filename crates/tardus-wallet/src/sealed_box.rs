//! Ed25519-keyed sealed-box AEAD (v5.5).
//!
//! Encrypts an arbitrary byte payload _to_ an ed25519 public key
//! (the recipient's "receiving identity") without the sender holding
//! any prior key material with the recipient. Decryption requires
//! the matching ed25519 private key.
//!
//! Construction follows the standard `NaCl` `crypto_box_seal` pattern:
//!
//!   1. Sender samples an ephemeral X25519 keypair `(esk, epk)`.
//!   2. Converts the recipient's ed25519 public key into its
//!      Montgomery (X25519) form `recipient_x25519`.
//!   3. Computes the ECDH shared secret
//!      `ss = esk · recipient_x25519`.
//!   4. Derives the AEAD key via
//!      `HKDF-SHA-256(salt = "TARDUS-sealed-box-v1",
//!                   ikm  = ss,
//!                   info = epk || recipient_x25519)`.
//!   5. Encrypts the payload with `ChaCha20-Poly1305`, with a
//!      deterministic nonce derived from the same HKDF (no
//!      sender-side state needed).
//!   6. Output wire format:
//!      `epk_32 || ciphertext_with_aead_tag`.
//!
//! Recipient inverts steps 1-5 using its ed25519 secret key. The
//! ephemeral key is forward-secret if `esk` is wiped after the
//! POST (which the sender does).
//!
//! Bound on adversary: an adversary who later compromises the
//! recipient's _ed25519_ private key can decrypt past traffic.
//! Forward secrecy with respect to recipient compromise is a v5.6
//! follow-up via "ratcheting".
//!
//! Padding is NOT applied at this layer; if the application wants
//! traffic-analysis resistance against length-side-channels it
//! should pre-pad to a fixed length.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use curve25519_dalek::{
    constants::X25519_BASEPOINT,
    edwards::CompressedEdwardsY,
    montgomery::MontgomeryPoint,
    scalar::Scalar,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

const HKDF_SALT: &[u8] = b"TARDUS-sealed-box-v1";
const NONCE_INFO: &[u8] = b"chacha20poly1305-nonce";
const KEY_INFO: &[u8] = b"chacha20poly1305-key";

/// Wire-format prefix length (the ephemeral X25519 pubkey).
pub const EPHEMERAL_KEY_LEN: usize = 32;

/// All v5.5 sealed-box failures.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("recipient ed25519 pubkey decode failure")]
    BadRecipient,
    #[error("sender ed25519 secret key decode failure")]
    BadSecret,
    #[error("sealed blob too short: {0} bytes (need at least {1})")]
    SealedTooShort(usize, usize),
    #[error("AEAD authentication failed")]
    AeadFailure,
}

/// Convert a 32-byte ed25519 compressed pubkey into its
/// Montgomery (X25519) form, per RFC 7748 §5 (the standard
/// Edwards↔Montgomery birational map).
fn ed25519_pub_to_x25519(pk: &[u8; 32]) -> Result<MontgomeryPoint, Error> {
    let cep = CompressedEdwardsY(*pk);
    let edwards = cep.decompress().ok_or(Error::BadRecipient)?;
    Ok(edwards.to_montgomery())
}

/// Convert a 32-byte ed25519 secret scalar into its X25519 scalar form.
/// We treat the ed25519 secret as the raw scalar (canonical form, as
/// used elsewhere in TARDUS — _not_ the SHA-512-pre-image form of
/// the BIP-32 derivation tree).
fn ed25519_secret_to_x25519(sk: &[u8; 32]) -> Result<Scalar, Error> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(*sk)).ok_or(Error::BadSecret)
}

fn derive_key_and_nonce(shared: &[u8], info1: &[u8], info2: &[u8]) -> (Zeroizing<[u8; 32]>, [u8; 12]) {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared);
    let mut key = Zeroizing::new([0u8; 32]);
    let mut info_buf = Vec::with_capacity(info1.len() + info2.len() + 16);
    info_buf.extend_from_slice(KEY_INFO);
    info_buf.extend_from_slice(info1);
    info_buf.extend_from_slice(info2);
    hk.expand(&info_buf, &mut *key).expect("hkdf 32 bytes infallible");

    let mut nonce_info = Vec::with_capacity(info1.len() + info2.len() + 16);
    nonce_info.extend_from_slice(NONCE_INFO);
    nonce_info.extend_from_slice(info1);
    nonce_info.extend_from_slice(info2);
    let mut nonce_bytes = [0u8; 12];
    hk.expand(&nonce_info, &mut nonce_bytes)
        .expect("hkdf 12 bytes infallible");
    (key, nonce_bytes)
}

/// Encrypt `plaintext` so only the holder of `recipient_ed25519_pk`'s
/// matching secret key can read it. Returns the wire bytes:
/// `ephemeral_x25519_pk(32) || ciphertext_with_aead_tag`.
///
/// # Errors
/// - [`Error::BadRecipient`] if `recipient_ed25519_pk` is not a
///   valid compressed Edwards point.
/// - [`Error::AeadFailure`] only on AEAD failure, practically
///   unreachable for ChaCha20-Poly1305 with a fresh key.
pub fn seal(plaintext: &[u8], recipient_ed25519_pk: &[u8; 32]) -> Result<Vec<u8>, Error> {
    let recipient_x = ed25519_pub_to_x25519(recipient_ed25519_pk)?;

    // Sample ephemeral X25519 keypair.
    let mut esk_bytes = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *esk_bytes);
    // Clamp per RFC 7748 §5.
    esk_bytes[0] &= 0b1111_1000;
    esk_bytes[31] &= 0b0111_1111;
    esk_bytes[31] |= 0b0100_0000;
    let esk = Scalar::from_bytes_mod_order(*esk_bytes);
    let epk = (esk * X25519_BASEPOINT).to_bytes();

    // ECDH shared secret.
    let shared = (esk * recipient_x).to_bytes();

    let (key, nonce_bytes) = derive_key_and_nonce(&shared, &epk, &recipient_x.to_bytes());
    let aead = ChaCha20Poly1305::new(Key::from_slice(&*key));
    let ct = aead
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|_| Error::AeadFailure)?;

    let mut out = Vec::with_capacity(EPHEMERAL_KEY_LEN + ct.len());
    out.extend_from_slice(&epk);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a `seal()` output using the matching ed25519 secret key
/// (raw 32-byte canonical scalar).
///
/// # Errors
/// - [`Error::SealedTooShort`] if `sealed` is shorter than the
///   ephemeral key + AEAD tag.
/// - [`Error::BadSecret`] if `recipient_ed25519_sk` is not a
///   canonical scalar.
/// - [`Error::AeadFailure`] if decryption rejects (wrong recipient,
///   tampered ciphertext).
pub fn open(sealed: &[u8], recipient_ed25519_sk: &[u8; 32]) -> Result<Vec<u8>, Error> {
    const MIN_LEN: usize = EPHEMERAL_KEY_LEN + 16;
    if sealed.len() < MIN_LEN {
        return Err(Error::SealedTooShort(sealed.len(), MIN_LEN));
    }
    let mut epk_bytes = [0u8; 32];
    epk_bytes.copy_from_slice(&sealed[..EPHEMERAL_KEY_LEN]);
    let ct = &sealed[EPHEMERAL_KEY_LEN..];
    let epk = MontgomeryPoint(epk_bytes);

    let sk_scalar = ed25519_secret_to_x25519(recipient_ed25519_sk)?;
    let shared = (sk_scalar * epk).to_bytes();

    // Recipient must recompute its own X25519 public form to match
    // the sender's `info2` in HKDF.
    let recipient_pub_x = (sk_scalar * X25519_BASEPOINT).to_bytes();
    let (key, nonce_bytes) = derive_key_and_nonce(&shared, &epk.to_bytes(), &recipient_pub_x);
    let aead = ChaCha20Poly1305::new(Key::from_slice(&*key));
    aead.decrypt(Nonce::from_slice(&nonce_bytes), ct)
        .map_err(|_| Error::AeadFailure)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> ([u8; 32], [u8; 32]) {
        // Derive an ed25519-style keypair from a random scalar.
        let mut sk_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut sk_bytes);
        let sk = Scalar::from_bytes_mod_order(sk_bytes);
        let sk_canon = sk.to_bytes();
        let pk = (sk * curve25519_dalek::constants::ED25519_BASEPOINT_POINT)
            .compress()
            .to_bytes();
        (sk_canon, pk)
    }

    #[test]
    fn seal_open_roundtrip() {
        let (sk, pk) = pair();
        let pt = b"the quick brown fox jumps over the lazy dog";
        let sealed = seal(pt, &pk).unwrap();
        assert!(sealed.len() >= EPHEMERAL_KEY_LEN + 16);
        let recovered = open(&sealed, &sk).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn wrong_recipient_rejected() {
        let (_alice_sk, alice_pk) = pair();
        let (bob_sk, _bob_pk) = pair();
        let sealed = seal(b"hidden", &alice_pk).unwrap();
        // Bob tries to open Alice's sealed box — must fail.
        let r = open(&sealed, &bob_sk);
        assert!(matches!(r, Err(Error::AeadFailure)));
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let (sk, pk) = pair();
        let mut sealed = seal(b"payload", &pk).unwrap();
        // Flip a byte in the ciphertext (past the 32-byte ephemeral pk).
        sealed[EPHEMERAL_KEY_LEN + 1] ^= 0x01;
        let r = open(&sealed, &sk);
        assert!(matches!(r, Err(Error::AeadFailure)));
    }

    #[test]
    fn ephemeral_key_varies_each_call() {
        let (_, pk) = pair();
        let s1 = seal(b"same plaintext", &pk).unwrap();
        let s2 = seal(b"same plaintext", &pk).unwrap();
        let epk1 = &s1[..EPHEMERAL_KEY_LEN];
        let epk2 = &s2[..EPHEMERAL_KEY_LEN];
        assert_ne!(epk1, epk2, "ephemeral key MUST be fresh per seal");
        // Ciphertexts likewise differ.
        assert_ne!(&s1[EPHEMERAL_KEY_LEN..], &s2[EPHEMERAL_KEY_LEN..]);
    }

    #[test]
    fn short_sealed_rejected() {
        let short = vec![0u8; 8];
        let sk = [0u8; 32];
        let r = open(&short, &sk);
        assert!(matches!(r, Err(Error::SealedTooShort(_, _))));
    }
}
