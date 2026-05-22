//! Coin model (spec §4.2).
//!
//! A TARDUS coin is the triple `(secret, pubkey_bytes, signature)`:
//! - `secret` (`SecretKey`): the spending key `x ∈ F_l`.
//! - `pubkey_bytes`: the compressed encoding of `Cp = x · G`.
//! - `signature`: a valid Schnorr signature on `pubkey_bytes` under
//!   the joint mint public key for the coin's denomination.
//!
//! Construction enforces `pubkey_bytes == (secret · G).compress()`,
//! preventing a malformed coin from existing.

use sha2::{Digest, Sha256};
use tardus_core::{schnorr_verify, PublicKey, SecretKey, Signature};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

/// Domain separator for nullifier computation (§4.2).
pub const NULLIFIER_DOMAIN: &[u8] = b"TARDUS-nullifier-v1";

/// A TARDUS coin. Secret material wiped on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Coin {
    secret: SecretKey,
    #[zeroize(skip)]
    pubkey_bytes: [u8; 32],
    #[zeroize(skip)]
    signature: Signature,
}

impl Coin {
    /// Construct a coin from its components.
    ///
    /// # Errors
    /// - [`Error::CoinPubkeyMismatch`] if `pubkey_bytes` is not the
    ///   canonical compression of `secret · G`.
    pub fn new(
        secret: SecretKey,
        pubkey_bytes: [u8; 32],
        signature: Signature,
    ) -> Result<Self> {
        let derived = PublicKey::from_secret(&secret);
        if derived.to_bytes() != pubkey_bytes {
            return Err(Error::CoinPubkeyMismatch);
        }
        Ok(Self {
            secret,
            pubkey_bytes,
            signature,
        })
    }

    /// The 32-byte compressed public commitment `Cp = secret · G`.
    #[must_use]
    pub fn pubkey_bytes(&self) -> [u8; 32] {
        self.pubkey_bytes
    }

    /// The mint's blind Schnorr signature on `pubkey_bytes`.
    #[must_use]
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Borrow the secret key (e.g. to spend the coin). Caller must
    /// treat the borrowed material with the same care as any
    /// `SecretKey`.
    #[must_use]
    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }

    /// Compute the nullifier: `SHA-256("TARDUS-nullifier-v1" || pubkey_bytes)`.
    ///
    /// The nullifier is what is inserted into the on-chain compressed
    /// nullifier tree (\Cref{sec:onchain}) when the coin is spent.
    /// Tying the nullifier to the public commitment `Cp` (not the
    /// secret `x`) is required for Solana SBF compatibility — the
    /// on-chain program cannot recompute `Cp = x · G` without
    /// triggering curve25519-dalek's variable-base scalar-mul
    /// lookup-table allocation, which exceeds the 4 KB SBF stack
    /// budget (see `research/PRODUCTION_LESSONS.md` §R8). Verifying
    /// the coin signature is delegated to the Solana
    /// `ed25519_program` precompile.
    #[must_use]
    pub fn nullifier(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(NULLIFIER_DOMAIN);
        hasher.update(self.pubkey_bytes);
        let out = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&out);
        bytes
    }

    /// Verify the coin's signature against a given joint public key.
    ///
    /// Returns `Ok(true)` for valid coins, `Ok(false)` for
    /// cryptographically well-formed but invalid coins, and `Err`
    /// for malformed signature material.
    ///
    /// # Errors
    /// - [`Error::Core`] if the signature is structurally malformed.
    pub fn verify(&self, joint_pk: &PublicKey) -> Result<bool> {
        schnorr_verify(joint_pk, &self.pubkey_bytes, &self.signature).map_err(Error::Core)
    }
}

impl core::fmt::Debug for Coin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Coin")
            .field("secret", &"<REDACTED>")
            .field("pubkey_bytes", &self.pubkey_bytes)
            .field("signature", &self.signature)
            .finish()
    }
}
