//! Hash functions used by `tardus-core`.
//!
//! `hash_to_scalar` implements `H_{F_l}` from spec §2.3, realised by
//! SHA-512 reduced modulo `l`. The reduction bias is bounded by
//! `l / 2^512 ≈ 2^{-260}`, which is negligible. A 256-bit hash
//! reduced modulo `l` would carry bias `≈ 2^{-4} = 6.25%`; we never use
//! that construction.

use alloc::vec::Vec;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

/// `H_{F_l}` --- map arbitrary bytes to an element of `F_l`.
#[must_use]
pub fn hash_to_scalar(input: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(input);
    let bytes = hasher.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(bytes.as_slice());
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Schnorr challenge hash `c = H_{F_l}(R || pk || m)` per spec §2.4.
#[must_use]
pub fn schnorr_challenge(r_compressed: &[u8; 32], pk: &[u8; 32], msg: &[u8]) -> Scalar {
    let mut data = Vec::with_capacity(64 + msg.len());
    data.extend_from_slice(r_compressed);
    data.extend_from_slice(pk);
    data.extend_from_slice(msg);
    hash_to_scalar(&data)
}
