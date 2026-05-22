//! Refresh protocol integration tests (spec §4.5).
//!
//! Crown jewel: full DKG → issue old coin (threshold blind sign on
//! coin pubkey) → 6-round cut-and-choose refresh → standard
//! `schnorr_verify` of new coin under joint_pk. Proves §4 protocol
//! correctness end-to-end.

#![allow(
    clippy::similar_names,
    clippy::unreadable_literal,
    clippy::doc_markdown,
    clippy::too_many_lines
)]

use std::time::Instant;

use rand::{rngs::OsRng, RngCore};
use tardus_core::{blind_request, unblind, PublicKey, SecretKey};
use tardus_mint::{
    dkg::{dkg_finalize, dkg_start, DkgFinalised, PeerContribution},
    sign::{
        aggregate_commitments, aggregate_responses, partial_sign, validator_round1,
        ValidatorR1Output, ValidatorR1State, ValidatorR3Output,
    },
    transcript::{CeremonyId, SessionId},
    vss::{h_generator, VssParameters},
};
use tardus_refresh::{
    coin::Coin,
    derivation::derive_coin_secret,
    error::Error,
    refresh::{
        aggregate_refresh_round1, aggregate_refresh_round5, compute_gamma_star,
        mint_refresh_round3, mint_refresh_verify_reveal, user_refresh_round2, user_refresh_round4,
        user_refresh_round6, validator_refresh_round1, validator_refresh_round5,
        RevealedCandidate, DEFAULT_KAPPA,
    },
};

const DKG_CEREMONY: CeremonyId = CeremonyId::from_bytes([0xAA; 16]);
const ISSUE_SESSION: SessionId = SessionId::from_bytes([0xBB; 16]);
const REFRESH_SESSION: SessionId = SessionId::from_bytes([0xCC; 16]);

// =====================================================================
// Helpers
// =====================================================================

fn run_dkg(n: u16, t: u16) -> Vec<DkgFinalised> {
    let mut rng = OsRng;
    let h = h_generator();
    let params = VssParameters::new(n, t).unwrap();
    let outputs: Vec<_> = (1..=n)
        .map(|i| dkg_start(DKG_CEREMONY, i, params, &h, &mut rng).unwrap())
        .collect();
    let mut finalisations = Vec::with_capacity(n as usize);
    for i in 1..=n {
        let i_idx = (i - 1) as usize;
        let received: Vec<PeerContribution> = (1..=n)
            .filter(|&k| k != i)
            .map(|k| {
                let k_idx = (k - 1) as usize;
                PeerContribution {
                    broadcast: outputs[k_idx].broadcast.clone(),
                    share_for_me: outputs[k_idx].shares[(i - 1) as usize].clone(),
                }
            })
            .collect();
        finalisations.push(dkg_finalize(&outputs[i_idx], &received, &h).unwrap());
    }
    finalisations
}

/// Threshold-blind-sign a message under the finalised committee.
fn run_threshold_blind_sign(
    finalised: &[DkgFinalised],
    t: u16,
    session_id: SessionId,
    msg: &[u8],
) -> tardus_core::Signature {
    let mut rng = OsRng;
    let signing_set: Vec<u16> = finalised.iter().take(t as usize).map(|f| f.my_index).collect();
    let joint_pk = finalised[0].joint_pk;

    let r1: Vec<(ValidatorR1Output, ValidatorR1State)> = signing_set
        .iter()
        .map(|&i| validator_round1(session_id, i, &mut rng))
        .collect();
    let r1_outputs: Vec<ValidatorR1Output> = r1.iter().map(|(out, _)| *out).collect();
    let blind_commit =
        aggregate_commitments(session_id, &signing_set, &r1_outputs).unwrap();
    let (challenge, user_state) = blind_request(&blind_commit, &joint_pk, msg, &mut rng).unwrap();
    let r3_outputs: Vec<ValidatorR3Output> = r1
        .iter()
        .map(|(_, state)| {
            let f_i = finalised.iter().find(|f| f.my_index == state.my_index).unwrap();
            partial_sign(state, &challenge, &f_i.my_share, &signing_set).unwrap()
        })
        .collect();
    let blind_response = aggregate_responses(session_id, &signing_set, &r3_outputs).unwrap();
    unblind(&user_state, &blind_response).unwrap()
}

/// Issue a fresh coin by performing threshold blind signing of the
/// coin's compressed public key under the joint mint key.
fn issue_coin(finalised: &[DkgFinalised], t: u16, session_id: SessionId) -> Coin {
    let mut rng = OsRng;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let x = derive_coin_secret(&seed);
    let sk = SecretKey::from_bytes(&x.to_bytes()).unwrap();
    let pk = PublicKey::from_secret(&sk);
    let cp_bytes = pk.to_bytes();
    let sig = run_threshold_blind_sign(finalised, t, session_id, &cp_bytes);
    Coin::new(sk, cp_bytes, sig).expect("coin construction with consistent inputs")
}

/// Run the full 6-round refresh protocol against the given committee.
fn run_full_refresh(
    finalised: &[DkgFinalised],
    t: u16,
    session_id: SessionId,
    kappa: u8,
    melted_coin: &Coin,
) -> Result<Coin, Error> {
    let mut rng = OsRng;
    let joint_pk = finalised[0].joint_pk;
    let signing_set: Vec<u16> = finalised.iter().take(t as usize).map(|f| f.my_index).collect();

    // Round 1: validators
    let mut val_round1: Vec<_> = Vec::with_capacity(t as usize);
    for &i in &signing_set {
        let (out, state) = validator_refresh_round1(session_id, i, kappa, &mut rng).unwrap();
        val_round1.push((out, state));
    }
    let r1_outputs: Vec<_> = val_round1.iter().map(|(o, _)| o.clone()).collect();

    // Aggregate round 1
    let mint_round1 = aggregate_refresh_round1(session_id, kappa, &signing_set, &r1_outputs)?;

    // Round 2: user
    let (user_round2, user_state) =
        user_refresh_round2(session_id, &mint_round1, &joint_pk, melted_coin, &mut rng)?;

    // Round 3: mint cut-and-choose
    let challenge = mint_refresh_round3(session_id, &user_round2, &joint_pk)?;

    // Round 4: user reveal
    let reveal = user_refresh_round4(&user_state, &challenge)?;

    // Mint verifies reveal
    mint_refresh_verify_reveal(&user_round2, &mint_round1, &challenge, &reveal, &joint_pk)?;

    // Round 5: validators sign γ*
    let mut r5_outputs = Vec::with_capacity(t as usize);
    for (_out, val_state) in &val_round1 {
        let f_i = finalised
            .iter()
            .find(|f| f.my_index == val_state.my_index)
            .unwrap();
        let r5 = validator_refresh_round5(
            val_state,
            &user_round2,
            &challenge,
            &f_i.my_share,
            &signing_set,
        )?;
        r5_outputs.push(r5);
    }
    let mint_round5 = aggregate_refresh_round5(session_id, &signing_set, &r5_outputs)?;

    // Round 6: user unblind
    user_refresh_round6(&user_state, &challenge, &mint_round5, &joint_pk)
}

// =====================================================================
// Crown jewel: end-to-end refresh
// =====================================================================

#[test]
fn refresh_n4_t3_kappa3_end_to_end() {
    let finalised = run_dkg(4, 3);
    let old_coin = issue_coin(&finalised, 3, ISSUE_SESSION);

    // The old coin verifies before refresh.
    assert!(
        old_coin.verify(&finalised[0].joint_pk).unwrap(),
        "freshly issued coin must verify"
    );

    let new_coin =
        run_full_refresh(&finalised, 3, REFRESH_SESSION, DEFAULT_KAPPA, &old_coin).unwrap();

    // The new coin MUST verify under the same joint_pk via standard
    // schnorr_verify. This is the operational proof that the
    // cut-and-choose refresh produced a cryptographically valid coin.
    assert!(
        new_coin.verify(&finalised[0].joint_pk).unwrap(),
        "refreshed new coin must verify under joint_pk via standard schnorr_verify"
    );
}

#[test]
fn refresh_new_coin_has_different_nullifier_than_old() {
    let finalised = run_dkg(4, 3);
    let old_coin = issue_coin(&finalised, 3, ISSUE_SESSION);
    let new_coin =
        run_full_refresh(&finalised, 3, REFRESH_SESSION, DEFAULT_KAPPA, &old_coin).unwrap();

    assert_ne!(
        old_coin.nullifier(),
        new_coin.nullifier(),
        "refresh must produce a coin with a distinct nullifier"
    );
}

#[test]
fn refresh_new_coin_has_different_pubkey_than_old() {
    let finalised = run_dkg(4, 3);
    let old_coin = issue_coin(&finalised, 3, ISSUE_SESSION);
    let new_coin =
        run_full_refresh(&finalised, 3, REFRESH_SESSION, DEFAULT_KAPPA, &old_coin).unwrap();

    assert_ne!(
        old_coin.pubkey_bytes(),
        new_coin.pubkey_bytes(),
        "new coin's Cp must be statistically independent of old coin's Cp"
    );
}

// =====================================================================
// Failure-mode tests
// =====================================================================

#[test]
fn refresh_bad_melted_coin_signature_rejected() {
    let finalised = run_dkg(4, 3);
    let mut bad_coin = issue_coin(&finalised, 3, ISSUE_SESSION);

    // Tamper the melted coin's signature.
    // (We re-construct because Coin holds sig privately; we use the
    // public field accessors then build a new Coin via raw deconstruction.)
    // Easier: reuse run_full_refresh with a manually-mangled R2 message.
    let mut rng = OsRng;
    let kappa = DEFAULT_KAPPA;
    let session_id = REFRESH_SESSION;
    let joint_pk = finalised[0].joint_pk;
    let signing_set: Vec<u16> = (1..=3u16).collect();

    let mut val_round1: Vec<_> = Vec::new();
    for &i in &signing_set {
        let (out, state) = validator_refresh_round1(session_id, i, kappa, &mut rng).unwrap();
        val_round1.push((out, state));
    }
    let r1_outputs: Vec<_> = val_round1.iter().map(|(o, _)| o.clone()).collect();
    let mint_round1 = aggregate_refresh_round1(session_id, kappa, &signing_set, &r1_outputs).unwrap();
    let (mut user_round2, _state) =
        user_refresh_round2(session_id, &mint_round1, &joint_pk, &bad_coin, &mut rng).unwrap();

    // Tamper the melted coin's signature in the round-2 message.
    user_round2.melted_coin_signature.s[0] ^= 0x01;
    let _ = &mut bad_coin; // silence

    match mint_refresh_round3(session_id, &user_round2, &joint_pk) {
        Err(Error::CoinSignatureInvalid) => {}
        other => panic!("expected CoinSignatureInvalid, got {other:?}"),
    }
}

#[test]
fn refresh_session_id_mismatch_rejected_at_round3() {
    let finalised = run_dkg(4, 3);
    let coin = issue_coin(&finalised, 3, ISSUE_SESSION);
    let mut rng = OsRng;
    let kappa = DEFAULT_KAPPA;
    let session_id = REFRESH_SESSION;
    let wrong_session = SessionId::from_bytes([0xDD; 16]);
    let joint_pk = finalised[0].joint_pk;
    let signing_set: Vec<u16> = (1..=3u16).collect();

    let mut val_round1: Vec<_> = Vec::new();
    for &i in &signing_set {
        let (out, state) = validator_refresh_round1(session_id, i, kappa, &mut rng).unwrap();
        val_round1.push((out, state));
    }
    let r1_outputs: Vec<_> = val_round1.iter().map(|(o, _)| o.clone()).collect();
    let mint_round1 = aggregate_refresh_round1(session_id, kappa, &signing_set, &r1_outputs).unwrap();
    let (user_round2, _) =
        user_refresh_round2(session_id, &mint_round1, &joint_pk, &coin, &mut rng).unwrap();

    // Mint round 3 with wrong session.
    match mint_refresh_round3(wrong_session, &user_round2, &joint_pk) {
        Err(Error::SessionIdMismatch) => {}
        other => panic!("expected SessionIdMismatch, got {other:?}"),
    }
}

#[test]
fn refresh_cheating_user_caught_at_reveal() {
    // Construct a refresh where the user tampers with one of the
    // revealed (seed, alpha, beta), so the recomputed c_γ' won't
    // match the submitted c_γ'.
    let finalised = run_dkg(4, 3);
    let coin = issue_coin(&finalised, 3, ISSUE_SESSION);
    let mut rng = OsRng;
    let kappa = DEFAULT_KAPPA;
    let session_id = REFRESH_SESSION;
    let joint_pk = finalised[0].joint_pk;
    let signing_set: Vec<u16> = (1..=3u16).collect();

    let mut val_round1: Vec<_> = Vec::new();
    for &i in &signing_set {
        let (out, state) = validator_refresh_round1(session_id, i, kappa, &mut rng).unwrap();
        val_round1.push((out, state));
    }
    let r1_outputs: Vec<_> = val_round1.iter().map(|(o, _)| o.clone()).collect();
    let mint_round1 = aggregate_refresh_round1(session_id, kappa, &signing_set, &r1_outputs).unwrap();
    let (user_round2, user_state) =
        user_refresh_round2(session_id, &mint_round1, &joint_pk, &coin, &mut rng).unwrap();
    let challenge = mint_refresh_round3(session_id, &user_round2, &joint_pk).unwrap();

    // Build a tampered reveal: replace one of the revealed candidate's
    // seed with a different fresh seed (so the recomputed c won't match).
    let mut reveal = user_refresh_round4(&user_state, &challenge).unwrap();
    let mut tampered_seed = reveal.revealed[0].seed;
    tampered_seed[0] ^= 0x01;
    reveal.revealed[0].seed = tampered_seed;

    match mint_refresh_verify_reveal(&user_round2, &mint_round1, &challenge, &reveal, &joint_pk) {
        Err(Error::CheatingDetected) => {}
        other => panic!("expected CheatingDetected, got {other:?}"),
    }
}

#[test]
fn refresh_user_reveals_gamma_star_rejected() {
    let finalised = run_dkg(4, 3);
    let coin = issue_coin(&finalised, 3, ISSUE_SESSION);
    let mut rng = OsRng;
    let kappa = DEFAULT_KAPPA;
    let session_id = REFRESH_SESSION;
    let joint_pk = finalised[0].joint_pk;
    let signing_set: Vec<u16> = (1..=3u16).collect();

    let mut val_round1: Vec<_> = Vec::new();
    for &i in &signing_set {
        let (out, state) = validator_refresh_round1(session_id, i, kappa, &mut rng).unwrap();
        val_round1.push((out, state));
    }
    let r1_outputs: Vec<_> = val_round1.iter().map(|(o, _)| o.clone()).collect();
    let mint_round1 = aggregate_refresh_round1(session_id, kappa, &signing_set, &r1_outputs).unwrap();
    let (user_round2, user_state) =
        user_refresh_round2(session_id, &mint_round1, &joint_pk, &coin, &mut rng).unwrap();
    let challenge = mint_refresh_round3(session_id, &user_round2, &joint_pk).unwrap();
    let mut reveal = user_refresh_round4(&user_state, &challenge).unwrap();

    // Inject γ* into the reveal list — a sneaky user trying to bypass.
    // Get a real (seed, alpha, beta) for γ* by hand-constructing.
    // We pretend the first revealed slot is now γ*.
    reveal.revealed[0] = RevealedCandidate {
        candidate_index: challenge.gamma_star,
        seed: [0u8; 32],
        alpha: [0u8; 32],
        beta: [0u8; 32],
    };

    match mint_refresh_verify_reveal(&user_round2, &mint_round1, &challenge, &reveal, &joint_pk) {
        Err(Error::CheatingDetected) => {}
        other => panic!("expected CheatingDetected, got {other:?}"),
    }
}

// =====================================================================
// gamma_star derivation
// =====================================================================

#[test]
fn gamma_star_is_in_range_and_deterministic() {
    for kappa in [2u8, 3, 5, 10] {
        for byte in 0u8..=255 {
            let sid = SessionId::from_bytes([byte; 16]);
            let g = compute_gamma_star(sid, kappa);
            assert!(g >= 1 && g <= kappa, "γ* must be in [1..κ]");
        }
        // Determinism
        let sid = SessionId::from_bytes([0x37; 16]);
        let g1 = compute_gamma_star(sid, kappa);
        let g2 = compute_gamma_star(sid, kappa);
        assert_eq!(g1, g2);
    }
}

// =====================================================================
// Performance
// =====================================================================

#[test]
fn perf_refresh_full_n4_t3_kappa3() {
    let finalised = run_dkg(4, 3);
    let coin = issue_coin(&finalised, 3, ISSUE_SESSION);
    let iter: u32 = 20;
    let start = Instant::now();
    let mut session_bytes = REFRESH_SESSION.to_bytes();
    for i in 0..iter {
        // Vary session_id to avoid γ* always being the same and to
        // exercise the gamma distribution.
        session_bytes[0] = u8::try_from(i & 0xff).unwrap();
        let session = SessionId::from_bytes(session_bytes);
        let _ = run_full_refresh(&finalised, 3, session, DEFAULT_KAPPA, &coin).unwrap();
    }
    let elapsed = start.elapsed();
    eprintln!(
        "[perf] full refresh (n=4, t=3, κ=3):    {:>10} ns/op  ({} iter, {:>5} ms total)",
        elapsed.as_nanos() / u128::from(iter),
        iter,
        elapsed.as_millis()
    );
}
