//! BIP-39 mnemonic key derivation for the wallet.
//!
//! Provides:
//!
//!   * [`generate_mnemonic`] — sample a fresh 12- or 24-word phrase
//!     from a CSPRNG.
//!   * [`derive_master_seed`] — PBKDF2-HMAC-SHA512(mnemonic, passphrase,
//!     2048 iterations) → 64 bytes → take first 32 as the wallet's
//!     master seed. This seed feeds [`tardus_refresh::coin::derive_coin_secret`]
//!     via the wallet's coin-secret HKDF (`tardus-client::issue`).
//!
//! The mnemonic itself is held only by the user; this module never
//! persists it. The derived master seed is what the wallet stores
//! encrypted on disk via [`tardus_client::backup`].
//!
//! Word lists default to BIP-39 English. Other locales can be added
//! by extending the `Language` enum forwarded from the `bip39` crate.

use crate::error::{Error, Result};
use bip39::{Language, Mnemonic};
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha512;
use zeroize::Zeroizing;

/// Number of words in a BIP-39 mnemonic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WordCount {
    Twelve = 12,
    TwentyFour = 24,
}

impl WordCount {
    /// BIP-39 entropy bytes for this word count
    /// (12 words ↔ 128 bits / 16 bytes; 24 words ↔ 256 bits / 32 bytes).
    #[must_use]
    pub const fn entropy_bytes(self) -> usize {
        match self {
            Self::Twelve => 16,
            Self::TwentyFour => 32,
        }
    }
}

/// Generate a fresh BIP-39 mnemonic from `OsRng`.
///
/// # Errors
/// `Error::Mint(_)` family if `bip39::Mnemonic::from_entropy_in`
/// fails (cannot happen given correct entropy size, but converted for
/// uniformity).
pub fn generate_mnemonic(word_count: WordCount) -> Result<Mnemonic> {
    let mut entropy = Zeroizing::new(vec![0u8; word_count.entropy_bytes()]);
    OsRng.fill_bytes(&mut entropy);
    Mnemonic::from_entropy_in(Language::English, &entropy).map_err(|e| {
        Error::ValidatorRejected {
            status: 0,
            body: format!("bip39: {e}"),
        }
    })
}

/// Derive the wallet's deterministic _receiving_ ed25519 keypair from
/// the master seed. Returns `(secret_canonical_bytes, pubkey_bytes)`.
///
/// The secret is computed as
/// `HKDF-SHA-512(salt = "TARDUS-recv-id-v1", ikm = master_seed)`
/// reduced mod `ℓ` (the ed25519 scalar field). The pubkey is
/// `secret · G`. This keypair is used by [`crate::sealed_box::seal`]
/// / `open` to encrypt P2P payloads (the recipient publishes their
/// pubkey via the `tardus://` invoice URI; the sealed box ensures
/// the relay payload-blind).
///
/// The receiving identity is intentionally _separate_ from any per-coin
/// secret: a wallet may share its receiving pubkey publicly without
/// any privacy loss for held coins.
///
/// # Panics
/// Cannot panic: `Hkdf::expand` with 64-byte output and a 64-byte
/// PRK is well within the algorithm's `255·HashLen` bound.
#[must_use]
pub fn derive_receiving_keypair(master_seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    const SALT: &[u8] = b"TARDUS-recv-id-v1";
    const INFO: &[u8] = b"ed25519-keypair";
    let hk = Hkdf::<Sha512>::new(Some(SALT), master_seed);
    let mut wide = Zeroizing::new([0u8; 64]);
    hk.expand(INFO, &mut *wide).expect("hkdf 64 bytes infallible");
    let sk = Scalar::from_bytes_mod_order_wide(&wide);
    let pk = (sk * ED25519_BASEPOINT_POINT).compress().to_bytes();
    (sk.to_bytes(), pk)
}

/// Original
/// passphrase. Internally runs BIP-39's PBKDF2-HMAC-SHA512 with 2048
/// iterations and returns the **first 32 bytes** of the 64-byte
/// BIP-39 seed (rest of the 32 bytes intentionally discarded — the
/// wallet doesn't use them).
#[must_use]
pub fn derive_master_seed(mnemonic: &Mnemonic, passphrase: &str) -> Zeroizing<[u8; 32]> {
    let seed64 = mnemonic.to_seed(passphrase);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&seed64[..32]);
    out
}

/// Parse a mnemonic from a whitespace-separated phrase string.
/// Validates checksum.
///
/// # Errors
/// `Error::ValidatorRejected` (re-used variant — clean type-error
/// hierarchy a v3.4 follow-up) if the phrase is malformed or the
/// checksum fails.
pub fn parse_mnemonic(phrase: &str) -> Result<Mnemonic> {
    Mnemonic::parse_in(Language::English, phrase).map_err(|e| Error::ValidatorRejected {
        status: 0,
        body: format!("bip39 parse: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_12_then_roundtrip() {
        let m = generate_mnemonic(WordCount::Twelve).unwrap();
        let phrase = m.to_string();
        assert_eq!(phrase.split_whitespace().count(), 12);
        let m2 = parse_mnemonic(&phrase).unwrap();
        assert_eq!(m.to_string(), m2.to_string());
    }

    #[test]
    fn generate_24_then_roundtrip() {
        let m = generate_mnemonic(WordCount::TwentyFour).unwrap();
        let phrase = m.to_string();
        assert_eq!(phrase.split_whitespace().count(), 24);
        let m2 = parse_mnemonic(&phrase).unwrap();
        assert_eq!(m.to_string(), m2.to_string());
    }

    #[test]
    fn derive_seed_is_deterministic() {
        let m = parse_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ).unwrap();
        let s1 = derive_master_seed(&m, "");
        let s2 = derive_master_seed(&m, "");
        assert_eq!(*s1, *s2);
    }

    #[test]
    fn passphrase_changes_derived_seed() {
        let m = parse_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ).unwrap();
        let no_pass = derive_master_seed(&m, "");
        let with_pass = derive_master_seed(&m, "TARDUS-wallet");
        assert_ne!(*no_pass, *with_pass);
    }

    #[test]
    fn receiving_keypair_is_deterministic_and_uses_sealed_box() {
        use crate::sealed_box::{open, seal};
        let m = parse_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let seed1 = derive_master_seed(&m, "");
        let seed2 = derive_master_seed(&m, "");
        assert_eq!(*seed1, *seed2);

        let (sk1, pk1) = derive_receiving_keypair(&seed1);
        let (sk2, pk2) = derive_receiving_keypair(&seed2);
        assert_eq!(sk1, sk2, "deterministic recv-keypair derivation");
        assert_eq!(pk1, pk2);

        // Roundtrip with sealed_box.
        let pt = b"sealed payload via mnemonic-derived recv keypair";
        let sealed = seal(pt, &pk1).unwrap();
        let recovered = open(&sealed, &sk1).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn parse_rejects_bad_checksum() {
        // Replace the last word with an invalid one for the standard
        // "abandon × 11" + "abandon" (which has a valid checksum) to
        // get a bad-checksum phrase.
        let bad =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        let r = parse_mnemonic(bad);
        assert!(r.is_err(), "bad-checksum mnemonic must be rejected");
    }
}
