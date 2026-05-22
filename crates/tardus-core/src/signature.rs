//! Single-party Schnorr signatures (spec §2.4).

use borsh::{BorshDeserialize, BorshSerialize};
use curve25519_dalek::{edwards::CompressedEdwardsY, scalar::Scalar};
use rand_core::CryptoRngCore;

use crate::{
    error::{Error, Result},
    group::{basepoint, PublicKey, SecretKey},
    hash::schnorr_challenge,
};

/// A Schnorr signature `(R, s)`.
///
/// `r` is the compressed Edwards-y encoding of the commitment point `R`.
/// `s` is the canonical little-endian encoding of the response scalar.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Signature {
    pub r: [u8; 32],
    pub s: [u8; 32],
}

impl Signature {
    /// 64-byte wire encoding: `R || s`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.r);
        out[32..].copy_from_slice(&self.s);
        out
    }

    /// Decode a 64-byte wire encoding without canonicality checks.
    /// Validity is enforced at `schnorr_verify` time.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);
        Self { r, s }
    }
}

/// Sign a message under the Schnorr scheme of spec §2.4.
///
/// The nonce `k` is sampled uniformly from `rng` --- this is necessary
/// for blind-signature compatibility (deterministic nonces would leak
/// the unblinded message to the signer).
pub fn schnorr_sign<R: CryptoRngCore + ?Sized>(
    sk: &SecretKey,
    pk: &PublicKey,
    msg: &[u8],
    rng: &mut R,
) -> Signature {
    let k = Scalar::random(rng);
    let r_pt = basepoint() * k;
    let r_bytes = r_pt.compress().to_bytes();
    let pk_bytes = pk.to_bytes();
    let c = schnorr_challenge(&r_bytes, &pk_bytes, msg);
    let s = k + c * sk.scalar();
    Signature {
        r: r_bytes,
        s: s.to_bytes(),
    }
}

/// Verify a Schnorr signature per spec §2.4.
///
/// Returns `Ok(true)` for valid signatures, `Ok(false)` for cryptographically
/// well-formed but invalid signatures, and `Err` for malformed inputs.
///
/// # Errors
/// Returns `Error::InvalidPoint` or `Error::InvalidScalar` if any field
/// of `sig` is not a canonical encoding.
pub fn schnorr_verify(pk: &PublicKey, msg: &[u8], sig: &Signature) -> Result<bool> {
    let pk_pt = pk.point()?;
    let r_compressed = CompressedEdwardsY(sig.r);
    let r_pt = r_compressed.decompress().ok_or(Error::InvalidPoint)?;
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(sig.s))
        .ok_or(Error::InvalidScalar)?;
    let pk_bytes = pk.to_bytes();
    let c = schnorr_challenge(&sig.r, &pk_bytes, msg);
    let lhs = basepoint() * s;
    let rhs = r_pt + pk_pt * c;
    Ok(lhs == rhs)
}
