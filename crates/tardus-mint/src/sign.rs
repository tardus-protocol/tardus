//! Threshold blind Schnorr signing session (spec §3.6, §2.9).
//!
//! Implements the validator side of the four-round threshold blind
//! Schnorr signing protocol. The user side is handled entirely by
//! `tardus_core::{blind_request, unblind}` operating against the joint
//! public key produced by [`crate::dkg::dkg_finalize`].
//!
//! The four rounds:
//!
//! 1. **Validator Round 1**: each `V_i ∈ S` samples `k_i ←$ F_l`,
//!    computes `R_i = k_i · G`, broadcasts `R_i`. The aggregator
//!    combines `R = Σ_{i ∈ S} R_i` and forwards `R` to the user.
//! 2. **User Round 2**: the user runs `tardus_core::blind_request` to
//!    blind `R` into `R'` and produce the blinded challenge `c`.
//! 3. **Validator Round 3**: each `V_i ∈ S` computes
//!    `s_i = k_i + c · λ_i^{(S)} · sk_i` where `λ_i^{(S)}` is the
//!    Lagrange coefficient at zero for `i` over the signing set `S`.
//!    The aggregator combines `s = Σ_{i ∈ S} s_i`.
//! 4. **User Round 4**: the user runs `tardus_core::unblind` to obtain
//!    the unblinded signature `(R', s')`, which verifies under the
//!    joint public key via the standard `tardus_core::schnorr_verify`.
//!
//! ## Nonce-reuse invariant (§3.6 Remark 3.1)
//!
//! A validator that participates with the same `(k_i, session_id)`
//! pair in two distinct invocations reveals its share via the standard
//! Schnorr nonce-reuse attack lifted to the threshold setting. The
//! mint protocol mandates HSM-enforced uniqueness of `(k_i, session_id)`;
//! this crate models the session ID in [`ValidatorR1State`] but does
//! not enforce the invariant. Enforcement happens at the validator
//! daemon layer (out of scope for this crate).

use alloc::vec::Vec;
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use rand_core::CryptoRngCore;
use tardus_core::{BlindChallenge, BlindCommit, BlindResponse, SecretKey};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    error::{Error, Result},
    transcript::SessionId,
};

// =====================================================================
// Types
// =====================================================================

/// Validator's private state between Rounds 1 and 3.
///
/// Holds the per-session nonce `k_i`. Wiped on drop. The HSM-enforced
/// unique-`(k_i, session_id)` invariant (§3.6 Remark 3.1) is the
/// responsibility of the validator daemon.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ValidatorR1State {
    #[zeroize(skip)]
    pub session_id: SessionId,
    #[zeroize(skip)]
    pub my_index: u16,
    pub(crate) k_i: Scalar,
}

/// What each validator broadcasts in Round 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatorR1Output {
    pub from_index: u16,
    pub session_id: SessionId,
    pub r_i: [u8; 32],
}

/// What each validator broadcasts in Round 3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatorR3Output {
    pub from_index: u16,
    pub session_id: SessionId,
    pub s_i: [u8; 32],
}

// =====================================================================
// Round 1 — Validator
// =====================================================================

/// Round 1 (validator): sample `k_i ←$ F_l`, compute `R_i = k_i · G`.
pub fn validator_round1<R: CryptoRngCore + ?Sized>(
    session_id: SessionId,
    my_index: u16,
    rng: &mut R,
) -> (ValidatorR1Output, ValidatorR1State) {
    let k_i = Scalar::random(rng);
    let r_i_pt = ED25519_BASEPOINT_POINT * k_i;
    let r_i_bytes = r_i_pt.compress().to_bytes();
    (
        ValidatorR1Output {
            from_index: my_index,
            session_id,
            r_i: r_i_bytes,
        },
        ValidatorR1State {
            session_id,
            my_index,
            k_i,
        },
    )
}

// =====================================================================
// Aggregation — Round 1 outputs → BlindCommit
// =====================================================================

/// Aggregator: sum the `R_i` commitments from all validators in
/// `signing_set` and produce a [`tardus_core::BlindCommit`] consumable
/// by the user via `tardus_core::blind_request`.
///
/// # Errors
/// - [`Error::InsufficientMessages`] if `outputs.len() != signing_set.len()`.
/// - [`Error::DomainMismatch`] if any output's `session_id` differs.
/// - [`Error::UnknownParticipant`] if any output's `from_index` is not in `signing_set`.
/// - [`Error::DuplicateParticipant`] if `outputs` contains duplicate indices.
/// - [`Error::Core`] if any `r_i` does not decode to a valid point.
pub fn aggregate_commitments(
    session_id: SessionId,
    signing_set: &[u16],
    outputs: &[ValidatorR1Output],
) -> Result<BlindCommit> {
    if outputs.len() != signing_set.len() {
        return Err(Error::InsufficientMessages);
    }

    let mut r_agg = EdwardsPoint::default();
    let mut seen: Vec<u16> = Vec::with_capacity(outputs.len());
    for out in outputs {
        if out.session_id != session_id {
            return Err(Error::DomainMismatch);
        }
        if !signing_set.contains(&out.from_index) {
            return Err(Error::UnknownParticipant);
        }
        if seen.contains(&out.from_index) {
            return Err(Error::DuplicateParticipant);
        }
        seen.push(out.from_index);

        let r_i = CompressedEdwardsY(out.r_i)
            .decompress()
            .ok_or(Error::Core(tardus_core::Error::InvalidPoint))?;
        r_agg += r_i;
    }

    Ok(BlindCommit {
        r: r_agg.compress().to_bytes(),
    })
}

// =====================================================================
// Round 3 — Validator
// =====================================================================

/// Round 3 (validator): compute partial signature
/// `s_i = k_i + c · λ_i^{(S)} · sk_i`.
///
/// `signing_set` MUST be the same set used to call
/// [`aggregate_commitments`]. The caller (validator daemon) must verify
/// this consistency; this function trusts the supplied set.
///
/// # Panics
/// Mathematically cannot panic: the `expect` is reached only on
/// `SecretKey::to_bytes()` output, which is always a canonical
/// scalar encoding.
///
/// # Errors
/// - [`Error::Core`] if `challenge.c` is not canonical.
/// - [`Error::UnknownParticipant`] if `state.my_index` not in `signing_set`.
/// - [`Error::InvalidSigningSet`] if `signing_set` contains 0 or duplicates.
pub fn partial_sign(
    state: &ValidatorR1State,
    challenge: &BlindChallenge,
    my_share: &SecretKey,
    signing_set: &[u16],
) -> Result<ValidatorR3Output> {
    let c = Option::<Scalar>::from(Scalar::from_canonical_bytes(challenge.c))
        .ok_or(Error::Core(tardus_core::Error::InvalidScalar))?;

    let lambda = lagrange_coefficient_at_zero(signing_set, state.my_index)?;

    let sk_bytes = Zeroizing::new(my_share.to_bytes());
    let sk_i = Option::<Scalar>::from(Scalar::from_canonical_bytes(*sk_bytes))
        .expect("SecretKey bytes are canonical by construction");

    let s_i = state.k_i + c * lambda * sk_i;

    Ok(ValidatorR3Output {
        from_index: state.my_index,
        session_id: state.session_id,
        s_i: s_i.to_bytes(),
    })
}

// =====================================================================
// Aggregation — Round 3 outputs → BlindResponse
// =====================================================================

/// Aggregator: sum the partial signatures from all validators and
/// produce a [`tardus_core::BlindResponse`] consumable by the user via
/// `tardus_core::unblind`.
///
/// # Errors
/// Same shape as [`aggregate_commitments`], plus
/// [`Error::Core`] if any `s_i` does not canonical-decode.
pub fn aggregate_responses(
    session_id: SessionId,
    signing_set: &[u16],
    outputs: &[ValidatorR3Output],
) -> Result<BlindResponse> {
    if outputs.len() != signing_set.len() {
        return Err(Error::InsufficientMessages);
    }

    let mut s_agg = Scalar::ZERO;
    let mut seen: Vec<u16> = Vec::with_capacity(outputs.len());
    for out in outputs {
        if out.session_id != session_id {
            return Err(Error::DomainMismatch);
        }
        if !signing_set.contains(&out.from_index) {
            return Err(Error::UnknownParticipant);
        }
        if seen.contains(&out.from_index) {
            return Err(Error::DuplicateParticipant);
        }
        seen.push(out.from_index);

        let s_i = Option::<Scalar>::from(Scalar::from_canonical_bytes(out.s_i))
            .ok_or(Error::Core(tardus_core::Error::InvalidScalar))?;
        s_agg += s_i;
    }

    Ok(BlindResponse {
        s: s_agg.to_bytes(),
    })
}

// =====================================================================
// Lagrange interpolation
// =====================================================================

/// Compute `λ_i^{(S)}(0) = Π_{k ∈ S, k ≠ i} (-k) / (i - k)` in `F_l`.
///
/// Used as the per-participant scaling factor when assembling a
/// threshold signature so that `Σ_i λ_i · sk_i = SK` (the joint
/// secret).
///
/// # Errors
/// - [`Error::UnknownParticipant`] if `i` is not in `signing_set`.
/// - [`Error::InvalidSigningSet`] if `signing_set` contains zero, or
///   if two distinct entries would produce a zero denominator
///   (duplicates).
pub fn lagrange_coefficient_at_zero(signing_set: &[u16], i: u16) -> Result<Scalar> {
    if !signing_set.contains(&i) {
        return Err(Error::UnknownParticipant);
    }
    if signing_set.contains(&0) {
        return Err(Error::InvalidSigningSet);
    }
    let i_scalar = Scalar::from(u64::from(i));
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    for &k in signing_set {
        if k == i {
            continue;
        }
        let k_scalar = Scalar::from(u64::from(k));
        num *= -k_scalar;
        let diff = i_scalar - k_scalar;
        if diff == Scalar::ZERO {
            return Err(Error::InvalidSigningSet);
        }
        den *= diff;
    }
    Ok(num * den.invert())
}
