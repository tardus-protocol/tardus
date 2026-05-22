//! κ-fold cut-and-choose refresh protocol (spec §4.5).
//!
//! Implements the validator and user sides of the six-round protocol
//! that exchanges one TARDUS coin for one fresh coin unlinkable to the
//! surrendered one. Threshold signing of the chosen candidate reuses
//! the per-validator and aggregator surface of `tardus-mint`.
//!
//! Round-by-round overview (spec §4.5):
//!
//! 1. Validator: sample κ nonces, broadcast R_{i,γ}.
//! 2. Aggregator: R_γ = Σ R_{i,γ}.
//! 3. User: for each γ ∈ [1..κ], derive a candidate coin secret from
//!    a fresh seed, blind the κ commitments, produce κ blinded
//!    challenges {c_γ}. Submit with the surrendered coin.
//! 4. Mint: pick γ* ∈ [1..κ] (deterministic from session_id in v1;
//!    production uses VRF).
//! 5. User: reveal {(seed_γ, α_γ, β_γ)} for all γ ≠ γ*.
//! 6. Mint: re-derive each revealed candidate, recompute c_γ, compare
//!    to submitted value. On match, validators compute partial
//!    signatures on c_{γ*}. Aggregator returns s_{γ*}.
//! 7. User: unblind s_{γ*} → new coin.

use alloc::vec::Vec;
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use rand_core::{CryptoRngCore, RngCore};
use sha2::{Digest, Sha256, Sha512};
use tardus_core::{PublicKey, SecretKey, Signature};
use tardus_mint::transcript::SessionId;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    coin::Coin,
    derivation::derive_coin_secret,
    error::{Error, Result},
};

// =====================================================================
// Constants
// =====================================================================

/// Default cut-and-choose parameter (§4 default).
pub const DEFAULT_KAPPA: u8 = 3;

/// Domain separator for γ* derivation from `session_id`.
const GAMMA_DOMAIN: &[u8] = b"TARDUS-refresh-cut-and-choose-v1";

// =====================================================================
// Validator-side types
// =====================================================================

/// What each validator broadcasts in Round 1 of refresh.
#[derive(Clone, Debug)]
pub struct ValidatorRefreshR1Output {
    pub session_id: SessionId,
    pub from_index: u16,
    /// `R_{i,γ}` for `γ ∈ [1..κ]`, in compressed Edwards-y form.
    pub r_per_candidate: Vec<[u8; 32]>,
}

/// Validator's private state across rounds 1 → 5. Wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ValidatorRefreshState {
    #[zeroize(skip)]
    pub session_id: SessionId,
    #[zeroize(skip)]
    pub my_index: u16,
    #[zeroize(skip)]
    pub kappa: u8,
    pub(crate) k_per_candidate: Vec<Scalar>,
}

/// Aggregated round-1 output (the mint's view).
#[derive(Clone, Debug)]
pub struct MintRefreshR1Output {
    pub session_id: SessionId,
    pub kappa: u8,
    /// `R_γ = Σ R_{i,γ}` for `γ ∈ [1..κ]`.
    pub aggregated_r_per_candidate: Vec<[u8; 32]>,
}

/// Mint's round-3 challenge: the cut-and-choose index γ*.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MintRefreshR3Challenge {
    pub session_id: SessionId,
    /// `γ* ∈ [1..κ]` (1-indexed).
    pub gamma_star: u8,
}

/// What each validator broadcasts in Round 5.
#[derive(Clone, Copy, Debug)]
pub struct ValidatorRefreshR5Output {
    pub session_id: SessionId,
    pub from_index: u16,
    pub s_partial: [u8; 32],
}

/// Aggregated round-5 response.
#[derive(Clone, Copy, Debug)]
pub struct MintRefreshR5Response {
    pub session_id: SessionId,
    pub s_aggregated: [u8; 32],
}

// =====================================================================
// User-side types
// =====================================================================

/// User's round-2 broadcast.
#[derive(Clone, Debug)]
pub struct UserRefreshR2Output {
    pub session_id: SessionId,
    pub kappa: u8,
    /// `c_γ` for `γ ∈ [1..κ]`.
    pub challenges: Vec<[u8; 32]>,
    /// The surrendered coin's public commitment.
    pub melted_coin_pubkey: [u8; 32],
    /// The surrendered coin's mint signature.
    pub melted_coin_signature: Signature,
}

/// User's private state across rounds 2 → 6. Wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UserRefreshState {
    #[zeroize(skip)]
    pub session_id: SessionId,
    #[zeroize(skip)]
    pub kappa: u8,
    #[zeroize(skip)]
    pub joint_pk_bytes: [u8; 32],
    pub(crate) seeds: Vec<[u8; 32]>,
    pub(crate) alphas: Vec<Scalar>,
    pub(crate) betas: Vec<Scalar>,
    #[zeroize(skip)]
    pub(crate) r_primes: Vec<[u8; 32]>,
}

/// One revealed candidate (γ' ≠ γ*) in Round 4.
#[derive(Clone, Copy, Debug)]
pub struct RevealedCandidate {
    /// `γ' ∈ [1..κ]`, not equal to `γ*`.
    pub candidate_index: u8,
    pub seed: [u8; 32],
    pub alpha: [u8; 32],
    pub beta: [u8; 32],
}

/// User's round-4 reveal: all κ-1 candidates other than γ*.
#[derive(Clone, Debug)]
pub struct UserRefreshR4Reveal {
    pub session_id: SessionId,
    pub revealed: Vec<RevealedCandidate>,
}

// =====================================================================
// Helpers
// =====================================================================

/// Compute `c_γ = H_{F_l}(R'_γ.compress() || joint_pk.compress() || msg_γ) + β_γ`.
/// Returns `(R'_γ, c_γ)`.
fn blind_one_candidate(
    r_aggregated: &EdwardsPoint,
    joint_pk_pt: &EdwardsPoint,
    joint_pk_bytes: &[u8; 32],
    alpha: &Scalar,
    beta: &Scalar,
    msg: &[u8],
) -> ([u8; 32], Scalar) {
    let r_prime_pt = r_aggregated + ED25519_BASEPOINT_POINT * alpha + joint_pk_pt * beta;
    let r_prime_bytes = r_prime_pt.compress().to_bytes();

    let mut hasher = Sha512::new();
    hasher.update(r_prime_bytes);
    hasher.update(joint_pk_bytes);
    hasher.update(msg);
    let hash = hasher.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash);
    let c_prime = Scalar::from_bytes_mod_order_wide(&wide);
    let c = c_prime + beta;

    (r_prime_bytes, c)
}

/// Compute `γ* = (SHA-256("TARDUS-refresh-cut-and-choose-v1" || session_id)[0] mod κ) + 1`.
///
/// Deterministic and verifiable for v1; production will use a
/// committee VRF output.
#[must_use]
pub fn compute_gamma_star(session_id: SessionId, kappa: u8) -> u8 {
    let mut hasher = Sha256::new();
    hasher.update(GAMMA_DOMAIN);
    hasher.update(session_id.to_bytes());
    let out = hasher.finalize();
    (out[0] % kappa) + 1
}

// =====================================================================
// Validator: Round 1
// =====================================================================

/// Round 1 (validator): sample κ nonces, return κ commitments.
///
/// # Errors
/// - [`Error::InvalidState`] if `kappa == 0`.
pub fn validator_refresh_round1<R: CryptoRngCore + ?Sized>(
    session_id: SessionId,
    my_index: u16,
    kappa: u8,
    rng: &mut R,
) -> Result<(ValidatorRefreshR1Output, ValidatorRefreshState)> {
    if kappa == 0 {
        return Err(Error::InvalidState);
    }
    let mut k_per_candidate = Vec::with_capacity(kappa as usize);
    let mut r_per_candidate = Vec::with_capacity(kappa as usize);
    for _ in 0..kappa {
        let k = Scalar::random(rng);
        let r_pt = ED25519_BASEPOINT_POINT * k;
        r_per_candidate.push(r_pt.compress().to_bytes());
        k_per_candidate.push(k);
    }
    Ok((
        ValidatorRefreshR1Output {
            session_id,
            from_index: my_index,
            r_per_candidate,
        },
        ValidatorRefreshState {
            session_id,
            my_index,
            kappa,
            k_per_candidate,
        },
    ))
}

// =====================================================================
// Aggregator: round-1
// =====================================================================

/// Aggregator: sum R_{i,γ} across validators in `signing_set` to
/// produce R_γ for each γ ∈ [1..κ].
///
/// # Errors
/// - [`Error::InvalidState`] if any output's kappa mismatches.
/// - [`Error::Mint`] for relay-validation failures.
pub fn aggregate_refresh_round1(
    session_id: SessionId,
    kappa: u8,
    signing_set: &[u16],
    outputs: &[ValidatorRefreshR1Output],
) -> Result<MintRefreshR1Output> {
    if outputs.len() != signing_set.len() {
        return Err(Error::Mint(tardus_mint::Error::InsufficientMessages));
    }
    if kappa == 0 {
        return Err(Error::InvalidState);
    }
    for out in outputs {
        if out.session_id != session_id {
            return Err(Error::SessionIdMismatch);
        }
        if out.r_per_candidate.len() != kappa as usize {
            return Err(Error::InvalidState);
        }
        if !signing_set.contains(&out.from_index) {
            return Err(Error::Mint(tardus_mint::Error::UnknownParticipant));
        }
    }
    // Detect duplicates
    let mut seen: Vec<u16> = Vec::with_capacity(outputs.len());
    for out in outputs {
        if seen.contains(&out.from_index) {
            return Err(Error::Mint(tardus_mint::Error::DuplicateParticipant));
        }
        seen.push(out.from_index);
    }

    let mut aggregated = Vec::with_capacity(kappa as usize);
    for gamma_idx in 0..(kappa as usize) {
        let mut agg = EdwardsPoint::default();
        for out in outputs {
            let r = CompressedEdwardsY(out.r_per_candidate[gamma_idx])
                .decompress()
                .ok_or(Error::Core(tardus_core::Error::InvalidPoint))?;
            agg += r;
        }
        aggregated.push(agg.compress().to_bytes());
    }

    Ok(MintRefreshR1Output {
        session_id,
        kappa,
        aggregated_r_per_candidate: aggregated,
    })
}

// =====================================================================
// User: Round 2
// =====================================================================

/// Round 2 (user): for each γ ∈ [1..κ], sample a seed, derive a
/// candidate coin secret, blind the mint's commitment, and produce
/// the blinded challenge. Returns the public round-2 output and the
/// secret state for use in rounds 4 and 6.
///
/// # Errors
/// - [`Error::SessionIdMismatch`] if `session_id` does not match the
///   mint's round-1 output.
/// - [`Error::Core`] for malformed `joint_pk`.
pub fn user_refresh_round2<R: CryptoRngCore + RngCore + ?Sized>(
    session_id: SessionId,
    mint_round1: &MintRefreshR1Output,
    joint_pk: &PublicKey,
    melted_coin: &Coin,
    rng: &mut R,
) -> Result<(UserRefreshR2Output, UserRefreshState)> {
    if mint_round1.session_id != session_id {
        return Err(Error::SessionIdMismatch);
    }
    let kappa = mint_round1.kappa;
    if kappa == 0 {
        return Err(Error::InvalidState);
    }

    let joint_pk_bytes = joint_pk.to_bytes();
    let joint_pk_pt = CompressedEdwardsY(joint_pk_bytes)
        .decompress()
        .ok_or(Error::Core(tardus_core::Error::InvalidPoint))?;

    let mut seeds: Vec<[u8; 32]> = Vec::with_capacity(kappa as usize);
    let mut alphas: Vec<Scalar> = Vec::with_capacity(kappa as usize);
    let mut betas: Vec<Scalar> = Vec::with_capacity(kappa as usize);
    let mut r_primes: Vec<[u8; 32]> = Vec::with_capacity(kappa as usize);
    let mut challenges: Vec<[u8; 32]> = Vec::with_capacity(kappa as usize);

    for gamma_idx in 0..(kappa as usize) {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);

        let x_gamma = derive_coin_secret(&seed);
        let cp_gamma = ED25519_BASEPOINT_POINT * x_gamma;
        let msg_gamma = cp_gamma.compress().to_bytes();

        let alpha = Scalar::random(rng);
        let beta = Scalar::random(rng);

        let r_aggregated = CompressedEdwardsY(mint_round1.aggregated_r_per_candidate[gamma_idx])
            .decompress()
            .ok_or(Error::Core(tardus_core::Error::InvalidPoint))?;

        let (r_prime, c) = blind_one_candidate(
            &r_aggregated,
            &joint_pk_pt,
            &joint_pk_bytes,
            &alpha,
            &beta,
            &msg_gamma,
        );

        seeds.push(seed);
        alphas.push(alpha);
        betas.push(beta);
        r_primes.push(r_prime);
        challenges.push(c.to_bytes());
    }

    let round2 = UserRefreshR2Output {
        session_id,
        kappa,
        challenges: challenges.clone(),
        melted_coin_pubkey: melted_coin.pubkey_bytes(),
        melted_coin_signature: *melted_coin.signature(),
    };

    let state = UserRefreshState {
        session_id,
        kappa,
        joint_pk_bytes,
        seeds,
        alphas,
        betas,
        r_primes,
    };

    Ok((round2, state))
}

// =====================================================================
// Mint: Round 3 (cut-and-choose)
// =====================================================================

/// Round 3 (mint): verify the melted coin's signature, then pick γ*.
///
/// # Errors
/// - [`Error::CoinSignatureInvalid`] if the melted coin does not verify.
/// - [`Error::SessionIdMismatch`] if session ids do not align.
pub fn mint_refresh_round3(
    session_id: SessionId,
    user_round2: &UserRefreshR2Output,
    joint_pk: &PublicKey,
) -> Result<MintRefreshR3Challenge> {
    if user_round2.session_id != session_id {
        return Err(Error::SessionIdMismatch);
    }
    // Verify melted coin signature.
    let ok = tardus_core::schnorr_verify(
        joint_pk,
        &user_round2.melted_coin_pubkey,
        &user_round2.melted_coin_signature,
    )?;
    if !ok {
        return Err(Error::CoinSignatureInvalid);
    }
    let gamma_star = compute_gamma_star(session_id, user_round2.kappa);
    Ok(MintRefreshR3Challenge {
        session_id,
        gamma_star,
    })
}

// =====================================================================
// User: Round 4 (reveal)
// =====================================================================

/// Round 4 (user): reveal seed, α, β for every candidate other than γ*.
///
/// # Errors
/// - [`Error::ChallengeOutOfRange`] if `gamma_star` is not in `[1..κ]`.
/// - [`Error::SessionIdMismatch`].
pub fn user_refresh_round4(
    state: &UserRefreshState,
    challenge: &MintRefreshR3Challenge,
) -> Result<UserRefreshR4Reveal> {
    if state.session_id != challenge.session_id {
        return Err(Error::SessionIdMismatch);
    }
    if challenge.gamma_star == 0 || challenge.gamma_star > state.kappa {
        return Err(Error::ChallengeOutOfRange);
    }
    let mut revealed = Vec::with_capacity((state.kappa - 1) as usize);
    for gamma in 1..=state.kappa {
        if gamma == challenge.gamma_star {
            continue;
        }
        let idx = (gamma - 1) as usize;
        revealed.push(RevealedCandidate {
            candidate_index: gamma,
            seed: state.seeds[idx],
            alpha: state.alphas[idx].to_bytes(),
            beta: state.betas[idx].to_bytes(),
        });
    }
    Ok(UserRefreshR4Reveal {
        session_id: state.session_id,
        revealed,
    })
}

// =====================================================================
// Mint: verify reveal
// =====================================================================

/// Mint: verify the user's reveal by re-deriving each revealed
/// candidate and comparing the recomputed `c_γ` to the user's
/// submitted value.
///
/// # Errors
/// - [`Error::SessionIdMismatch`] across messages.
/// - [`Error::ChallengeOutOfRange`] if a revealed `candidate_index`
///   is invalid.
/// - [`Error::CheatingDetected`] if any recomputed `c_γ` does not
///   match the submitted `c_γ`.
/// - [`Error::Core`] for malformed scalars/points.
pub fn mint_refresh_verify_reveal(
    user_round2: &UserRefreshR2Output,
    mint_round1: &MintRefreshR1Output,
    challenge: &MintRefreshR3Challenge,
    reveal: &UserRefreshR4Reveal,
    joint_pk: &PublicKey,
) -> Result<()> {
    if user_round2.session_id != challenge.session_id
        || reveal.session_id != challenge.session_id
        || mint_round1.session_id != challenge.session_id
    {
        return Err(Error::SessionIdMismatch);
    }
    let kappa = user_round2.kappa;
    if reveal.revealed.len() != (kappa - 1) as usize {
        return Err(Error::CheatingDetected);
    }

    let joint_pk_bytes = joint_pk.to_bytes();
    let joint_pk_pt = CompressedEdwardsY(joint_pk_bytes)
        .decompress()
        .ok_or(Error::Core(tardus_core::Error::InvalidPoint))?;

    let mut seen: Vec<u8> = Vec::with_capacity(reveal.revealed.len());
    for rc in &reveal.revealed {
        if rc.candidate_index == 0 || rc.candidate_index > kappa {
            return Err(Error::ChallengeOutOfRange);
        }
        if rc.candidate_index == challenge.gamma_star {
            // User must not reveal the chosen candidate.
            return Err(Error::CheatingDetected);
        }
        if seen.contains(&rc.candidate_index) {
            return Err(Error::CheatingDetected);
        }
        seen.push(rc.candidate_index);

        let idx = (rc.candidate_index - 1) as usize;
        let x_gamma = derive_coin_secret(&rc.seed);
        let cp_gamma = ED25519_BASEPOINT_POINT * x_gamma;
        let msg_gamma = cp_gamma.compress().to_bytes();

        let alpha = Option::<Scalar>::from(Scalar::from_canonical_bytes(rc.alpha))
            .ok_or(Error::Core(tardus_core::Error::InvalidScalar))?;
        let beta = Option::<Scalar>::from(Scalar::from_canonical_bytes(rc.beta))
            .ok_or(Error::Core(tardus_core::Error::InvalidScalar))?;

        let r_agg = CompressedEdwardsY(mint_round1.aggregated_r_per_candidate[idx])
            .decompress()
            .ok_or(Error::Core(tardus_core::Error::InvalidPoint))?;

        let (_, c_recomputed) = blind_one_candidate(
            &r_agg,
            &joint_pk_pt,
            &joint_pk_bytes,
            &alpha,
            &beta,
            &msg_gamma,
        );

        if c_recomputed.to_bytes() != user_round2.challenges[idx] {
            return Err(Error::CheatingDetected);
        }
    }
    Ok(())
}

// =====================================================================
// Validator: Round 5
// =====================================================================

/// Round 5 (validator): compute the partial signature on the γ*-th
/// challenge.
///
/// # Panics
/// Mathematically cannot panic: `SecretKey::to_bytes()` is canonical.
///
/// # Errors
/// - [`Error::ChallengeOutOfRange`] if γ* is out of range.
/// - [`Error::SessionIdMismatch`].
/// - [`Error::Core`] for malformed scalar input.
/// - [`Error::Mint`] for Lagrange computation failure.
pub fn validator_refresh_round5(
    val_state: &ValidatorRefreshState,
    user_round2: &UserRefreshR2Output,
    challenge: &MintRefreshR3Challenge,
    my_share: &SecretKey,
    signing_set: &[u16],
) -> Result<ValidatorRefreshR5Output> {
    if val_state.session_id != challenge.session_id
        || user_round2.session_id != challenge.session_id
    {
        return Err(Error::SessionIdMismatch);
    }
    if challenge.gamma_star == 0 || challenge.gamma_star > val_state.kappa {
        return Err(Error::ChallengeOutOfRange);
    }
    let idx = (challenge.gamma_star - 1) as usize;
    let c_bytes = user_round2.challenges[idx];
    let c = Option::<Scalar>::from(Scalar::from_canonical_bytes(c_bytes))
        .ok_or(Error::Core(tardus_core::Error::InvalidScalar))?;

    let lambda = tardus_mint::sign::lagrange_coefficient_at_zero(signing_set, val_state.my_index)
        .map_err(Error::Mint)?;

    let sk_bytes = my_share.to_bytes();
    let sk_scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(sk_bytes))
        .expect("SecretKey bytes are canonical by construction");

    let k_i_gamma = val_state.k_per_candidate[idx];
    let s_i = k_i_gamma + c * lambda * sk_scalar;

    Ok(ValidatorRefreshR5Output {
        session_id: val_state.session_id,
        from_index: val_state.my_index,
        s_partial: s_i.to_bytes(),
    })
}

// =====================================================================
// Aggregator: round-5
// =====================================================================

/// Aggregator: sum partial signatures and produce the mint's round-5
/// response.
///
/// # Errors
/// Same shape as [`aggregate_refresh_round1`].
pub fn aggregate_refresh_round5(
    session_id: SessionId,
    signing_set: &[u16],
    outputs: &[ValidatorRefreshR5Output],
) -> Result<MintRefreshR5Response> {
    if outputs.len() != signing_set.len() {
        return Err(Error::Mint(tardus_mint::Error::InsufficientMessages));
    }
    let mut s_agg = Scalar::ZERO;
    let mut seen: Vec<u16> = Vec::with_capacity(outputs.len());
    for out in outputs {
        if out.session_id != session_id {
            return Err(Error::SessionIdMismatch);
        }
        if !signing_set.contains(&out.from_index) {
            return Err(Error::Mint(tardus_mint::Error::UnknownParticipant));
        }
        if seen.contains(&out.from_index) {
            return Err(Error::Mint(tardus_mint::Error::DuplicateParticipant));
        }
        seen.push(out.from_index);
        let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(out.s_partial))
            .ok_or(Error::Core(tardus_core::Error::InvalidScalar))?;
        s_agg += s;
    }
    Ok(MintRefreshR5Response {
        session_id,
        s_aggregated: s_agg.to_bytes(),
    })
}

// =====================================================================
// User: Round 6 (unblind)
// =====================================================================

/// Round 6 (user): unblind the aggregated signature and emit the new
/// coin.
///
/// # Panics
/// Cannot panic: scalar/point conversions only fail on malformed
/// inputs that are caught by upstream validation.
///
/// # Errors
/// - [`Error::SessionIdMismatch`].
/// - [`Error::ChallengeOutOfRange`].
/// - [`Error::Core`] for malformed scalar inputs.
/// - [`Error::CoinSignatureInvalid`] if the unblinded signature fails
///   to verify under `joint_pk` (sanity check).
pub fn user_refresh_round6(
    state: &UserRefreshState,
    challenge: &MintRefreshR3Challenge,
    response: &MintRefreshR5Response,
    joint_pk: &PublicKey,
) -> Result<Coin> {
    if state.session_id != challenge.session_id || response.session_id != challenge.session_id {
        return Err(Error::SessionIdMismatch);
    }
    if challenge.gamma_star == 0 || challenge.gamma_star > state.kappa {
        return Err(Error::ChallengeOutOfRange);
    }
    let idx = (challenge.gamma_star - 1) as usize;

    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(response.s_aggregated))
        .ok_or(Error::Core(tardus_core::Error::InvalidScalar))?;
    let alpha = state.alphas[idx];
    let s_prime = s + alpha;

    let r_prime = state.r_primes[idx];

    // Re-derive the new coin's secret from the same seed (deterministic).
    let x = derive_coin_secret(&state.seeds[idx]);
    let secret = SecretKey::from_bytes(&x.to_bytes())
        .expect("derived scalar is canonical by construction");
    let pubkey = PublicKey::from_secret(&secret);

    let sig = Signature {
        r: r_prime,
        s: s_prime.to_bytes(),
    };

    // Sanity check: the unblinded signature MUST verify under joint_pk.
    let ok = tardus_core::schnorr_verify(joint_pk, &pubkey.to_bytes(), &sig)?;
    if !ok {
        return Err(Error::CoinSignatureInvalid);
    }

    Coin::new(secret, pubkey.to_bytes(), sig)
}
