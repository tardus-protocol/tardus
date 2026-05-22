//! Group and scalar wrappers for `tardus-core`.
//!
//! `SecretKey` wraps a `Scalar` and is zeroised on drop. `PublicKey`
//! wraps a `CompressedEdwardsY` and exposes only the byte serialisation
//! to callers.

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

/// The standard base point `G` of the prime-order subgroup of edwards25519.
#[inline]
#[must_use]
pub fn basepoint() -> EdwardsPoint {
    ED25519_BASEPOINT_POINT
}

/// A TARDUS secret key --- a scalar in `F_l`.
///
/// Secret material is wiped from memory when the key is dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(pub(crate) Scalar);

impl SecretKey {
    /// Sample a uniform secret key from a cryptographically-strong RNG.
    pub fn random<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        Self(Scalar::random(rng))
    }

    /// Decode a 32-byte canonical scalar.
    ///
    /// # Errors
    /// Returns `Error::InvalidScalar` if `bytes` is not the canonical
    /// little-endian encoding of an element of `F_l`.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes))
            .map(Self)
            .ok_or(Error::InvalidScalar)
    }

    /// Canonical 32-byte little-endian encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub(crate) fn scalar(&self) -> &Scalar {
        &self.0
    }
}

/// A TARDUS public key --- a point in the prime-order subgroup of
/// edwards25519, in compressed Edwards-y form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey(pub(crate) CompressedEdwardsY);

impl PublicKey {
    /// Derive the public key `pk = sk * G` from a secret key.
    #[must_use]
    pub fn from_secret(sk: &SecretKey) -> Self {
        Self((basepoint() * sk.0).compress())
    }

    /// Decode a 32-byte compressed Edwards-y encoding.
    ///
    /// # Errors
    /// Returns `Error::InvalidPoint` if `bytes` is not a valid
    /// compressed encoding of a point in the prime-order subgroup.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let compressed = CompressedEdwardsY(*bytes);
        let pt = compressed.decompress().ok_or(Error::InvalidPoint)?;
        if pt.is_torsion_free() {
            Ok(Self(compressed))
        } else {
            Err(Error::InvalidPoint)
        }
    }

    /// Canonical 32-byte compressed Edwards-y encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub(crate) fn point(&self) -> Result<EdwardsPoint> {
        self.0.decompress().ok_or(Error::InvalidPoint)
    }
}

/// A complete keypair: secret + derived public.
pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl Keypair {
    /// Generate a fresh keypair from an RNG.
    pub fn random<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        let secret = SecretKey::random(rng);
        let public = PublicKey::from_secret(&secret);
        Self { secret, public }
    }
}
