//! Distributed Key Generation ceremony (spec §3.4).
//!
//! Implementation v1: happy-path joint-Feldman-Pedersen DKG following
//! Gennaro-Jarecki-Krawczyk-Rabin 1999 §4.1 with the round-1
//! collapsing of Komlo-Goldberg 2020. Each validator:
//!
//! 1. Generates a secret contribution `s_i ∈ F_l` and a uniformly
//!    sampled polynomial pair `(f_i, g_i)` with `f_i(0) = s_i` and
//!    `g_i(0) = r_i`.
//! 2. Publishes Pedersen commitments `C_k = a_k·G + b_k·H` (for share
//!    verification) and Feldman commitments `A_k = a_k·G` (for joint
//!    key derivation), and a Schnorr proof of knowledge of `s_i`
//!    against `A_0 = s_i·G`.
//! 3. Privately delivers share `(f_i(j), g_i(j))` to each peer `j`.
//!
//! After exchange, each party verifies all peer POKs and incoming
//! shares. The joint public key is `PK = Σ_i A_{i,0}`; the party's
//! final secret share is `sk_j = Σ_i f_i(j)`.
//!
//! v1 covers the happy path: all `n` participants are assumed
//! responsive. Complaint handling and the qualified-set logic with
//! removal are deferred to v1.2d.2 (round-2 of the spec).

use alloc::vec::Vec;
use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};
use rand_core::CryptoRngCore;
use tardus_core::{schnorr_sign, schnorr_verify, PublicKey, SecretKey, Signature};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    error::{Error, Result},
    transcript::{CeremonyId, CEREMONY_DOMAIN},
    vss::{deal, verify_share, FeldmanCommitments, VssCommitments, VssParameters, VssShare},
};

// =====================================================================
// Domain-separated POK message
// =====================================================================

const POK_DOMAIN_INFIX: &[u8] = b":dkg-pok:";

/// Build the canonical POK message:
/// `CEREMONY_DOMAIN || ":dkg-pok:" || ceremony_id || from_index_le_u16`.
fn build_pok_msg(ceremony_id: CeremonyId, from_index: u16) -> Vec<u8> {
    let mut msg = Vec::with_capacity(CEREMONY_DOMAIN.len() + POK_DOMAIN_INFIX.len() + 16 + 2);
    msg.extend_from_slice(CEREMONY_DOMAIN);
    msg.extend_from_slice(POK_DOMAIN_INFIX);
    msg.extend_from_slice(&ceremony_id.to_bytes());
    msg.extend_from_slice(&from_index.to_le_bytes());
    msg
}

// =====================================================================
// Round-1 broadcast and private state
// =====================================================================

/// What each validator broadcasts in Round 1 of the DKG ceremony.
#[derive(Clone, Debug, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct DkgRound1Broadcast {
    pub ceremony_id: CeremonyId,
    pub from_index: u16,
    pub pedersen: VssCommitments,
    pub feldman: FeldmanCommitments,
    pub pok: Signature,
}

/// A validator's private Round-1 state. Held until [`dkg_finalize`].
/// Wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DkgRound1Private {
    #[zeroize(skip)]
    pub ceremony_id: CeremonyId,
    #[zeroize(skip)]
    pub my_index: u16,
    #[zeroize(skip)]
    pub params: VssParameters,
    pub(crate) my_secret: Scalar,
}

/// Output of [`dkg_start`]. Contains the broadcast, the private state,
/// and the full set of shares (one per peer, indexed `1..=n` including
/// the dealer's own self-share at position `my_index - 1`).
pub struct DkgRound1Output {
    pub broadcast: DkgRound1Broadcast,
    pub private: DkgRound1Private,
    pub shares: Vec<VssShare>,
}

/// What a party receives from each peer: the peer's broadcast plus the
/// private share intended for this party.
#[derive(Clone, Debug, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct PeerContribution {
    pub broadcast: DkgRound1Broadcast,
    pub share_for_me: VssShare,
}

// =====================================================================
// Finalisation
// =====================================================================

/// The output of a successful DKG ceremony for one validator.
pub struct DkgFinalised {
    pub my_index: u16,
    pub joint_pk: PublicKey,
    pub my_share: SecretKey,
    /// Indices of all participants whose contributions are included
    /// in the joint key (the qualified set).
    pub qual: Vec<u16>,
}

// Manual `Debug` that redacts the secret share. Joint PK and qual
// are public; my_share is wiped on drop and never printed.
impl core::fmt::Debug for DkgFinalised {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DkgFinalised")
            .field("my_index", &self.my_index)
            .field("joint_pk", &self.joint_pk)
            .field("my_share", &"<REDACTED>")
            .field("qual", &self.qual)
            .finish()
    }
}

// =====================================================================
// dkg_start
// =====================================================================

/// Start the DKG ceremony for a single validator.
///
/// Generates the validator's secret contribution `s_i`, computes the
/// Pedersen+Feldman commitments, signs a proof-of-knowledge of `s_i`,
/// and returns the broadcast, private state, and the full share set
/// `[f_i(j), g_i(j)]` for `j ∈ 1..=n`.
///
/// # Panics
/// Mathematically cannot panic: the `expect` calls cover construction
/// of `SecretKey`/`PublicKey` from byte encodings that are guaranteed
/// canonical (output of `Scalar::to_bytes` and `EdwardsPoint::compress`).
///
/// # Errors
/// - [`Error::UnknownParticipant`] if `my_index` is not in `1..=params.n`.
pub fn dkg_start<R: CryptoRngCore + ?Sized>(
    ceremony_id: CeremonyId,
    my_index: u16,
    params: VssParameters,
    h_gen: &EdwardsPoint,
    rng: &mut R,
) -> Result<DkgRound1Output> {
    if my_index == 0 || my_index > params.n {
        return Err(Error::UnknownParticipant);
    }

    let my_secret = Scalar::random(rng);
    let (pedersen, feldman, shares) = deal(&my_secret, params, h_gen, rng);

    // Build POK: Schnorr signature with secret = s_i, public key = A_{i,0}.
    let sk_bytes = Zeroizing::new(my_secret.to_bytes());
    let sk = SecretKey::from_bytes(&sk_bytes).expect("Scalar::to_bytes() is always canonical");
    let pk_bytes = feldman.secret_commitment().compress().to_bytes();
    let pk = PublicKey::from_bytes(&pk_bytes).expect("s·G is always a valid prime-order point");
    let msg = build_pok_msg(ceremony_id, my_index);
    let pok = schnorr_sign(&sk, &pk, &msg, rng);

    let broadcast = DkgRound1Broadcast {
        ceremony_id,
        from_index: my_index,
        pedersen,
        feldman,
        pok,
    };
    let private = DkgRound1Private {
        ceremony_id,
        my_index,
        params,
        my_secret,
    };

    Ok(DkgRound1Output {
        broadcast,
        private,
        shares,
    })
}

// =====================================================================
// Verification
// =====================================================================

/// Verify a peer's Round-1 proof of knowledge of `s_i` against
/// `A_{i,0} = s_i · G`.
///
/// # Errors
/// - [`Error::Core`] if the Feldman secret commitment is not a valid
///   prime-order point.
/// - [`Error::PokInvalid`] if the signature does not verify.
pub fn verify_round1_pok(broadcast: &DkgRound1Broadcast) -> Result<()> {
    let pk_bytes = broadcast.feldman.secret_commitment().compress().to_bytes();
    let pk = PublicKey::from_bytes(&pk_bytes)?;
    let msg = build_pok_msg(broadcast.ceremony_id, broadcast.from_index);
    let ok = schnorr_verify(&pk, &msg, &broadcast.pok)?;
    if ok {
        Ok(())
    } else {
        Err(Error::PokInvalid)
    }
}

// =====================================================================
// dkg_finalize
// =====================================================================

/// Finalise the DKG ceremony for the calling validator.
///
/// Verifies every peer's POK and incoming share, then computes:
/// - The joint public key `PK = Σ_i A_{i,0}` (over self + received).
/// - This validator's final secret share `sk_j = Σ_i f_i(j)`.
///
/// # Panics
/// Mathematically cannot panic: the `expect` on `SecretKey::from_bytes`
/// is reached only after summing canonical scalars, whose sum mod
/// `l` is itself canonical.
///
/// # Errors
/// - [`Error::InsufficientMessages`] if the wrong number of peer
///   contributions were supplied (must equal `params.n - 1`).
/// - [`Error::DomainMismatch`] if any received share's index does not
///   match `my_index`, or a peer's `from_index` collides with `my_index`.
/// - [`Error::PokInvalid`] if any POK does not verify.
/// - [`Error::VssShareInvalid`] if any incoming share does not verify
///   against the dealer's Pedersen commitments.
/// - [`Error::DuplicateParticipant`] if any peer index appears twice.
pub fn dkg_finalize(
    own: &DkgRound1Output,
    received: &[PeerContribution],
    h_gen: &EdwardsPoint,
) -> Result<DkgFinalised> {
    let my_index = own.private.my_index;
    let expected_received = usize::from(own.private.params.n) - 1;
    if received.len() != expected_received {
        return Err(Error::InsufficientMessages);
    }

    // Verify own POK as a sanity check.
    verify_round1_pok(&own.broadcast)?;

    // Track seen peer indices to detect duplicates / self-collisions.
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

        verify_round1_pok(&peer.broadcast)?;
        verify_share(&peer.share_for_me, &peer.broadcast.pedersen, h_gen)?;
    }

    // Joint public key: PK = Σ_i A_{i,0}  for i ∈ {self} ∪ received.
    let mut joint_pk_pt = *own.broadcast.feldman.secret_commitment();
    for peer in received {
        joint_pk_pt += peer.broadcast.feldman.secret_commitment();
    }
    let joint_pk_bytes = joint_pk_pt.compress().to_bytes();
    let joint_pk = PublicKey::from_bytes(&joint_pk_bytes)?;

    // My final share: sk_j = Σ_i f_i(j) over i ∈ {self} ∪ received.
    let self_share = &own.shares[(my_index - 1) as usize];
    let self_f = Option::<Scalar>::from(Scalar::from_canonical_bytes(self_share.f_share_bytes()))
        .ok_or(Error::VssShareInvalid)?;
    let mut sum_f = self_f;
    for peer in received {
        let f_i =
            Option::<Scalar>::from(Scalar::from_canonical_bytes(peer.share_for_me.f_share_bytes()))
                .ok_or(Error::VssShareInvalid)?;
        sum_f += f_i;
    }

    // Wrap as SecretKey (auto-zeroising). The intermediate bytes are
    // held in a Zeroizing guard so they cannot linger on stack.
    let share_bytes = Zeroizing::new(sum_f.to_bytes());
    let my_share = SecretKey::from_bytes(&share_bytes)
        .expect("sum of canonical scalars is canonical");

    let mut qual = seen_indices;
    qual.sort_unstable();

    Ok(DkgFinalised {
        my_index,
        joint_pk,
        my_share,
        qual,
    })
}
