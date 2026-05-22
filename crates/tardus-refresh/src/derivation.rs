//! Coin secret derivation (spec §4.4).
//!
//! HKDF-SHA-512 with a 512-bit output reduced modulo `l` for negligible
//! reduction bias (`~2^{-260}`). The input is a fresh, one-shot 256-bit
//! seed: deterministic-from-wallet-seed derivation (BIP32-style) is
//! explicitly forbidden per the Cashu NUT-13 lesson
//! (`research/PRODUCTION_LESSONS.md` §L2).

use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

/// HKDF salt for refresh-context derivations.
pub const REFRESH_DOMAIN: &[u8] = b"TARDUS-refresh-v1";

/// HKDF info string for the per-candidate coin secret derivation.
pub const COIN_SECRET_INFO: &[u8] = b"coin-secret";

/// Derive a coin secret scalar from a uniform 256-bit seed.
///
/// `seed` MUST be a freshly-sampled cryptographic random value used
/// exactly once. Reusing a seed for two different coin secrets is
/// equivalent to reusing a nonce in Schnorr signing and is forbidden.
///
/// # Panics
/// Cannot panic: `Hkdf::expand` with a 64-byte output and a 32-byte
/// salt always succeeds (the spec-imposed maximum length for SHA-512
/// HKDF expand is `255 × 64 = 16,320` bytes).
#[must_use]
pub fn derive_coin_secret(seed: &[u8; 32]) -> Scalar {
    let hkdf = Hkdf::<Sha512>::new(Some(REFRESH_DOMAIN), seed);
    let mut okm = Zeroizing::new([0u8; 64]);
    hkdf.expand(COIN_SECRET_INFO, okm.as_mut())
        .expect("HKDF-Expand of 64 bytes always succeeds");
    Scalar::from_bytes_mod_order_wide(&okm)
}
