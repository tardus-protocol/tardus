//! Proactive secret-sharing rotation (spec §3.7).
//!
//! Re-randomises each validator's secret share without changing the
//! joint public key. The construction is a degree-`t-1` "zero
//! polynomial" reshare: each validator samples `f̃_i(x)` with
//! `f̃_i(0) = 0` and shares `f̃_i(j)` with peer `j`. After exchange,
//! each validator updates its share as
//!
//! ```text
//!   sk_j^{(e+1)} = sk_j^{(e)} + Σ_i f̃_i(j) (mod l)
//! ```
//!
//! Because `Σ_i f̃_i(0) = 0`, Lagrange reconstruction of the new
//! shares yields the same joint secret as the old shares, and
//! therefore `joint_pk` is preserved across rotation.
//!
//! Soundness against a cheating dealer that tries to shift the joint
//! key requires the explicit verifier check `Ã_{i,0} == identity`,
//! since `Ã_{i,0} = a_{i,0} · G = f̃_i(0) · G`. A non-identity
//! commitment is rejected with [`Error::ResharePolyNonZero`].
//!
//! No proof-of-knowledge is required because the "secret" is
//! publicly known to be `0`; the identity check serves the same
//! purpose (publicly attests `s_i = 0`).

use alloc::vec::Vec;
use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar, traits::IsIdentity};
use rand_core::CryptoRngCore;
use tardus_core::SecretKey;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    error::{Error, Result},
    transcript::CeremonyId,
    vss::{deal, verify_share, FeldmanCommitments, VssCommitments, VssParameters, VssShare},
};

// =====================================================================
// Types
// =====================================================================

/// What each validator broadcasts in Round 1 of the reshare ceremony.
/// Mirrors `DkgRound1Broadcast` but carries no proof-of-knowledge —
/// the secret is publicly `0`, attested by `Ã_0 == identity`.
#[derive(Clone, Debug, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ReshareRound1Broadcast {
    pub ceremony_id: CeremonyId,
    pub from_index: u16,
    pub pedersen: VssCommitments,
    pub feldman: FeldmanCommitments,
}

/// A validator's private bookkeeping for the reshare ceremony.
/// The "secret" is fixed at `0`, so this struct holds only metadata.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ReshareRound1Private {
    #[zeroize(skip)]
    pub ceremony_id: CeremonyId,
    #[zeroize(skip)]
    pub my_index: u16,
    #[zeroize(skip)]
    pub params: VssParameters,
}

/// Output of [`reshare_start`].
pub struct ReshareRound1Output {
    pub broadcast: ReshareRound1Broadcast,
    pub private: ReshareRound1Private,
    /// Shares for peers, indexed `1..=n` (including self-share at
    /// position `my_index - 1`).
    pub shares: Vec<VssShare>,
}

/// A peer's contribution received during reshare.
#[derive(Clone, Debug, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ResharePeerContribution {
    pub broadcast: ReshareRound1Broadcast,
    pub share_for_me: VssShare,
}

/// Output of [`reshare_finalize`]: the validator's new share. Joint
/// PK is unchanged by rotation; the caller already holds it.
pub struct ReshareFinalised {
    pub my_index: u16,
    pub new_share: SecretKey,
    pub qual: Vec<u16>,
}

impl core::fmt::Debug for ReshareFinalised {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReshareFinalised")
            .field("my_index", &self.my_index)
            .field("new_share", &"<REDACTED>")
            .field("qual", &self.qual)
            .finish()
    }
}

// =====================================================================
// Reshare start
// =====================================================================

/// Start the reshare ceremony for a single validator.
///
/// Internally calls `vss::deal(&Scalar::ZERO, ...)`, then asserts
/// that the resulting Feldman secret commitment is the identity
/// point (which it must be, since `0 · G = identity`).
///
/// # Errors
/// - [`Error::UnknownParticipant`] if `my_index ∉ 1..=params.n`.
pub fn reshare_start<R: CryptoRngCore + ?Sized>(
    ceremony_id: CeremonyId,
    my_index: u16,
    params: VssParameters,
    h_gen: &EdwardsPoint,
    rng: &mut R,
) -> Result<ReshareRound1Output> {
    if my_index == 0 || my_index > params.n {
        return Err(Error::UnknownParticipant);
    }

    let zero_secret = Scalar::ZERO;
    let (pedersen, feldman, shares) = deal(&zero_secret, params, h_gen, rng);

    // Sanity invariant: the Feldman secret commitment MUST be identity.
    // This is automatic given the zero secret, but we assert as a
    // self-check against algebraic errors.
    debug_assert!(
        feldman.secret_commitment().is_identity(),
        "reshare invariant: Feldman secret commitment must be identity"
    );

    let broadcast = ReshareRound1Broadcast {
        ceremony_id,
        from_index: my_index,
        pedersen,
        feldman,
    };
    let private = ReshareRound1Private {
        ceremony_id,
        my_index,
        params,
    };

    Ok(ReshareRound1Output {
        broadcast,
        private,
        shares,
    })
}

// =====================================================================
// Verification
// =====================================================================

/// Verify a peer's reshare broadcast: the Feldman secret commitment
/// must be the identity point. (Pedersen share verification is
/// performed separately at finalize time, per share.)
///
/// # Errors
/// - [`Error::ResharePolyNonZero`] if `Ã_0 ≠ identity`.
pub fn verify_reshare_round1(broadcast: &ReshareRound1Broadcast) -> Result<()> {
    if broadcast.feldman.secret_commitment().is_identity() {
        Ok(())
    } else {
        Err(Error::ResharePolyNonZero)
    }
}

// =====================================================================
// Reshare finalize
// =====================================================================

/// Finalise the reshare ceremony for the calling validator.
///
/// Verifies every peer's reshare broadcast (`Ã_0 == identity`) and
/// every incoming share against the corresponding Pedersen
/// commitments. Computes the new share as
/// `sk_j^{new} = sk_j^{old} + Σ_{i ∈ {self} ∪ received} f̃_i(j) (mod l)`.
///
/// # Panics
/// Mathematically cannot panic: `SecretKey::from_bytes` is reached
/// only after summing canonical scalars, whose sum mod `l` is
/// canonical.
///
/// # Errors
/// Same shape as [`crate::dkg::dkg_finalize`], plus
/// [`Error::ResharePolyNonZero`] for any peer whose `Ã_0` is not
/// identity.
pub fn reshare_finalize(
    own: &ReshareRound1Output,
    old_share: &SecretKey,
    received: &[ResharePeerContribution],
    h_gen: &EdwardsPoint,
) -> Result<ReshareFinalised> {
    let my_index = own.private.my_index;
    let expected_received = usize::from(own.private.params.n) - 1;
    if received.len() != expected_received {
        return Err(Error::InsufficientMessages);
    }

    // Verify own broadcast as a sanity check.
    verify_reshare_round1(&own.broadcast)?;

    let mut seen_indices: Vec<u16> = Vec::with_capacity(received.len() + 1);
    seen_indices.push(my_index);

    for peer in received {
        if peer.broadcast.from_index == my_index {
            return Err(Error::DomainMismatch);
        }
        if seen_indices.contains(&peer.broadcast.from_index) {
            return Err(Error::DuplicateParticipant);
        }
        seen_indices.push(peer.broadcast.from_index);

        if peer.share_for_me.index() != my_index {
            return Err(Error::DomainMismatch);
        }
        if peer.broadcast.ceremony_id != own.private.ceremony_id {
            return Err(Error::DomainMismatch);
        }

        verify_reshare_round1(&peer.broadcast)?;
        verify_share(&peer.share_for_me, &peer.broadcast.pedersen, h_gen)?;
    }

    // Sum reshare shares: own self-share + each peer's share_for_me.
    let self_share = &own.shares[(my_index - 1) as usize];
    let self_f = Option::<Scalar>::from(Scalar::from_canonical_bytes(self_share.f_share_bytes()))
        .ok_or(Error::VssShareInvalid)?;
    let mut delta = self_f;
    for peer in received {
        let f_i =
            Option::<Scalar>::from(Scalar::from_canonical_bytes(peer.share_for_me.f_share_bytes()))
                .ok_or(Error::VssShareInvalid)?;
        delta += f_i;
    }

    // New share = old share + delta.
    let old_bytes = Zeroizing::new(old_share.to_bytes());
    let old_scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(*old_bytes))
        .expect("SecretKey bytes are canonical by construction");
    let new_scalar = old_scalar + delta;

    let new_bytes = Zeroizing::new(new_scalar.to_bytes());
    let new_share = SecretKey::from_bytes(&new_bytes)
        .expect("sum of canonical scalars is canonical");

    let mut qual = seen_indices;
    qual.sort_unstable();

    Ok(ReshareFinalised {
        my_index,
        new_share,
        qual,
    })
}
