//! Blind Schnorr signatures (spec §2.5).
//!
//! The four-round protocol is exposed as four independent functions
//! and three intermediate state types:
//!
//! 1. `issue_round1` --- signer commits to `R = kG`, returns
//!    `BlindCommit` and a `SignerState` (holding `k`).
//! 2. `blind_request` --- user blinds the commitment with random
//!    `(α, β)`, computes the blinded challenge `c`, returns
//!    `BlindChallenge` and a `UserState`.
//! 3. `issue_round2` --- signer produces `s = k + c·sk`, wrapped in
//!    `BlindResponse`.
//! 4. `unblind` --- user computes `s' = s + α`, returning the
//!    unblinded `Signature` valid under `pk`.

use curve25519_dalek::{edwards::CompressedEdwardsY, scalar::Scalar};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    error::{Error, Result},
    group::{basepoint, PublicKey, SecretKey},
    hash::schnorr_challenge,
    signature::Signature,
};

/// Signer's round-1 output: commitment `R` (compressed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlindCommit {
    pub r: [u8; 32],
}

/// Signer's private state across rounds 1 → 3.
///
/// Holds the nonce `k`; must be retained until `issue_round2` is called
/// with the user's challenge. Wiped on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SignerState {
    pub(crate) k: Scalar,
}

/// User's round-2 output: blinded challenge `c`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlindChallenge {
    pub c: [u8; 32],
}

/// User's private state across rounds 2 → 4.
///
/// Holds the unblinding factors `(α, β)` and the unblinded commitment
/// `R'` that will be part of the final signature. Wiped on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct UserState {
    pub(crate) alpha: Scalar,
    pub(crate) beta: Scalar,
    pub(crate) r_prime: [u8; 32],
}

/// Signer's round-3 output: blinded response `s`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlindResponse {
    pub s: [u8; 32],
}

/// Round 1 --- signer samples `k`, sends `R = kG`.
pub fn issue_round1<R: CryptoRngCore + ?Sized>(rng: &mut R) -> (BlindCommit, SignerState) {
    let k = Scalar::random(rng);
    let r_bytes = (basepoint() * k).compress().to_bytes();
    (BlindCommit { r: r_bytes }, SignerState { k })
}

/// Round 2 --- user blinds `R` with random `(α, β)`,
/// computes `R' = R + αG + β·pk`, `c' = H(R' || pk || m)`,
/// `c = c' + β`, sends `c`.
///
/// # Errors
/// Returns `Error::InvalidPoint` if `commit.r` does not decode to a
/// valid edwards25519 point, or if `pk` is invalid.
pub fn blind_request<R: CryptoRngCore + ?Sized>(
    commit: &BlindCommit,
    pk: &PublicKey,
    msg: &[u8],
    rng: &mut R,
) -> Result<(BlindChallenge, UserState)> {
    let r_pt = CompressedEdwardsY(commit.r)
        .decompress()
        .ok_or(Error::InvalidPoint)?;
    let pk_pt = pk.point()?;

    let alpha = Scalar::random(rng);
    let beta = Scalar::random(rng);
    let r_prime_pt = r_pt + basepoint() * alpha + pk_pt * beta;
    let r_prime_bytes = r_prime_pt.compress().to_bytes();

    let pk_bytes = pk.to_bytes();
    let c_prime = schnorr_challenge(&r_prime_bytes, &pk_bytes, msg);
    let c = c_prime + beta;

    Ok((
        BlindChallenge { c: c.to_bytes() },
        UserState {
            alpha,
            beta,
            r_prime: r_prime_bytes,
        },
    ))
}

/// Round 3 --- signer computes `s = k + c·sk`.
///
/// # Errors
/// Returns `Error::InvalidScalar` if `challenge.c` is not canonical.
pub fn issue_round2(
    state: &SignerState,
    challenge: &BlindChallenge,
    sk: &SecretKey,
) -> Result<BlindResponse> {
    let c = Option::<Scalar>::from(Scalar::from_canonical_bytes(challenge.c))
        .ok_or(Error::InvalidScalar)?;
    let s = state.k + c * sk.scalar();
    Ok(BlindResponse { s: s.to_bytes() })
}

/// Round 4 --- user computes `s' = s + α` and emits the final signature
/// `(R', s')` valid under `pk` per spec §2.4.
///
/// # Errors
/// Returns `Error::InvalidScalar` if `response.s` is not canonical.
pub fn unblind(state: &UserState, response: &BlindResponse) -> Result<Signature> {
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(response.s))
        .ok_or(Error::InvalidScalar)?;
    let s_prime = s + state.alpha;
    Ok(Signature {
        r: state.r_prime,
        s: s_prime.to_bytes(),
    })
}
