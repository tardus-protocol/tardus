//! Threshold blind Schnorr signing integration tests (spec §3.6, §2.9).
//!
//! The crown jewel test exercises the full four-round protocol:
//! DKG → threshold Round 1 (R_i broadcast) → user blind_request →
//! threshold Round 3 (partial sign s_i) → user unblind → standard
//! `schnorr_verify` against the joint public key. The signature
//! produced via threshold blind issuance must verify under the joint
//! key with the standard, non-threshold-aware verifier — this is the
//! verifiable security property of the construction.

#![allow(
    clippy::similar_names,
    clippy::unreadable_literal,
    clippy::doc_markdown
)]

use std::time::Instant;

use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use tardus_core::{blind_request, schnorr_verify, unblind};
use tardus_mint::{
    dkg::{dkg_finalize, dkg_start, DkgFinalised, PeerContribution},
    error::Error,
    sign::{
        aggregate_commitments, aggregate_responses, lagrange_coefficient_at_zero, partial_sign,
        validator_round1, ValidatorR1Output, ValidatorR1State, ValidatorR3Output,
    },
    transcript::{CeremonyId, SessionId},
    vss::{h_generator, VssParameters},
};

const DKG_CEREMONY: CeremonyId = CeremonyId::from_bytes([0xAA; 16]);
const SIGN_SESSION: SessionId = SessionId::from_bytes([0xBB; 16]);

// =====================================================================
// Helpers
// =====================================================================

fn run_dkg_simulation(n: u16, t: u16) -> Vec<DkgFinalised> {
    let mut rng = OsRng;
    let h = h_generator();
    let params = VssParameters::new(n, t).expect("valid params");
    let outputs: Vec<_> = (1..=n)
        .map(|i| dkg_start(DKG_CEREMONY, i, params, &h, &mut rng).expect("dkg_start"))
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
        finalisations
            .push(dkg_finalize(&outputs[i_idx], &received, &h).expect("dkg_finalize"));
    }
    finalisations
}

/// Run a full threshold blind signing session for `msg` against a
/// committee whose first `t` finalisations form the signing set.
/// Returns the resulting signature.
fn run_threshold_blind_sign(
    finalised: &[DkgFinalised],
    t: u16,
    session_id: SessionId,
    msg: &[u8],
) -> tardus_core::Signature {
    let mut rng = OsRng;
    let signing_set: Vec<u16> = finalised.iter().take(t as usize).map(|f| f.my_index).collect();
    let joint_pk = finalised[0].joint_pk;

    // Round 1: each validator in signing_set
    let r1: Vec<(ValidatorR1Output, ValidatorR1State)> = signing_set
        .iter()
        .map(|&i| validator_round1(session_id, i, &mut rng))
        .collect();
    let r1_outputs: Vec<ValidatorR1Output> = r1.iter().map(|(out, _)| *out).collect();

    // Aggregator: combine R_i
    let blind_commit =
        aggregate_commitments(session_id, &signing_set, &r1_outputs).expect("aggregate_commitments");

    // User: blind request
    let (challenge, user_state) =
        blind_request(&blind_commit, &joint_pk, msg, &mut rng).expect("blind_request");

    // Round 3: each validator computes s_i
    let r3_outputs: Vec<ValidatorR3Output> = r1
        .iter()
        .map(|(_, state)| {
            let f_i = finalised
                .iter()
                .find(|f| f.my_index == state.my_index)
                .expect("validator share present");
            partial_sign(state, &challenge, &f_i.my_share, &signing_set).expect("partial_sign")
        })
        .collect();

    // Aggregator: combine s_i
    let blind_response =
        aggregate_responses(session_id, &signing_set, &r3_outputs).expect("aggregate_responses");

    // User: unblind
    unblind(&user_state, &blind_response).expect("unblind")
}

// =====================================================================
// Crown jewel: end-to-end threshold blind signing
// =====================================================================

#[test]
fn threshold_blind_sign_end_to_end_n4_t3() {
    let finalised = run_dkg_simulation(4, 3);
    let msg = b"TARDUS threshold blind sign v1 - n=4 t=3";
    let sig = run_threshold_blind_sign(&finalised, 3, SIGN_SESSION, msg);

    // The resulting signature MUST verify under the standard Schnorr
    // verifier (not aware of threshold), against the joint_pk.
    assert!(
        schnorr_verify(&finalised[0].joint_pk, msg, &sig).unwrap(),
        "threshold blind signature MUST verify under standard schnorr_verify on joint_pk"
    );
}

#[test]
fn threshold_blind_sign_invalid_under_wrong_message() {
    let finalised = run_dkg_simulation(4, 3);
    let sig = run_threshold_blind_sign(&finalised, 3, SIGN_SESSION, b"original");
    let verifies_under_wrong = schnorr_verify(&finalised[0].joint_pk, b"different", &sig).unwrap();
    assert!(!verifies_under_wrong, "signature must not verify against a different message");
}

#[test]
fn threshold_blind_sign_invalid_under_wrong_pk() {
    let finalised_a = run_dkg_simulation(4, 3);
    let finalised_b = run_dkg_simulation(4, 3);
    let msg = b"target";
    let sig = run_threshold_blind_sign(&finalised_a, 3, SIGN_SESSION, msg);
    let verifies_under_wrong =
        schnorr_verify(&finalised_b[0].joint_pk, msg, &sig).unwrap();
    assert!(!verifies_under_wrong, "signature must not verify under a different joint_pk");
}

// =====================================================================
// Lagrange coefficient sanity
// =====================================================================

#[test]
fn lagrange_coefficient_known_values_t2() {
    // For signing set {1, 2}, λ_1(0) = (-2) / (1 - 2) = -2 / -1 = 2.
    //                       λ_2(0) = (-1) / (2 - 1) = -1 / 1 = -1.
    let s = [1u16, 2];
    let l1 = lagrange_coefficient_at_zero(&s, 1).unwrap();
    let l2 = lagrange_coefficient_at_zero(&s, 2).unwrap();
    assert_eq!(l1, Scalar::from(2u64));
    assert_eq!(l2, -Scalar::from(1u64));
}

#[test]
fn lagrange_coefficients_sum_to_one_for_constant_polynomial() {
    // For any signing set S and any subset thereof of size t:
    //   Σ_{i ∈ S} λ_i(0) = 1   (Lagrange identity at 0 for constant 1)
    let sets: [&[u16]; 4] = [&[1, 2], &[1, 2, 3], &[2, 5, 11, 13], &[3, 7, 9, 11, 17]];
    for s in &sets {
        let mut sum = Scalar::ZERO;
        for &i in *s {
            sum += lagrange_coefficient_at_zero(s, i).unwrap();
        }
        assert_eq!(sum, Scalar::ONE, "Σ λ_i(0) must equal 1 for set {s:?}");
    }
}

#[test]
fn lagrange_rejects_unknown_index() {
    let s = [1u16, 2, 3];
    assert!(matches!(
        lagrange_coefficient_at_zero(&s, 4),
        Err(Error::UnknownParticipant)
    ));
}

#[test]
fn lagrange_rejects_zero_in_set() {
    let s = [0u16, 1, 2];
    let result = lagrange_coefficient_at_zero(&s, 1);
    assert!(matches!(result, Err(Error::InvalidSigningSet)));
}

// =====================================================================
// Aggregation validation
// =====================================================================

#[test]
fn aggregate_commitments_rejects_wrong_session_id() {
    let mut rng = OsRng;
    let (out, _state) = validator_round1(SIGN_SESSION, 1, &mut rng);
    let wrong = SessionId::from_bytes([0xCC; 16]);
    let result = aggregate_commitments(wrong, &[1], &[out]);
    assert!(matches!(result, Err(Error::DomainMismatch)));
}

#[test]
fn aggregate_commitments_rejects_unknown_participant() {
    let mut rng = OsRng;
    let (out, _state) = validator_round1(SIGN_SESSION, 5, &mut rng);
    // signing_set is [1,2,3], but the output says from_index=5
    let result = aggregate_commitments(SIGN_SESSION, &[1, 2, 3], &[out]);
    assert!(matches!(result, Err(Error::InsufficientMessages))); // first check: counts mismatch
}

#[test]
fn aggregate_commitments_rejects_duplicate_participants() {
    let mut rng = OsRng;
    let (out_a, _) = validator_round1(SIGN_SESSION, 1, &mut rng);
    let (out_b, _) = validator_round1(SIGN_SESSION, 1, &mut rng);
    let result = aggregate_commitments(SIGN_SESSION, &[1, 2], &[out_a, out_b]);
    assert!(matches!(result, Err(Error::DuplicateParticipant)));
}

// =====================================================================
// Performance
// =====================================================================

#[test]
fn perf_threshold_blind_sign_n4_t3() {
    let finalised = run_dkg_simulation(4, 3);
    let msg = b"perf payload";
    let iter: u32 = 50;
    let start = Instant::now();
    for _ in 0..iter {
        let _ = run_threshold_blind_sign(&finalised, 3, SIGN_SESSION, msg);
    }
    let elapsed = start.elapsed();
    eprintln!(
        "[perf] threshold_blind_sign (n=4, t=3):   {:>10} ns/op  ({} iter, {:>5} ms total)",
        elapsed.as_nanos() / u128::from(iter),
        iter,
        elapsed.as_millis()
    );
}

#[test]
fn perf_threshold_blind_sign_n30_t14() {
    let finalised = run_dkg_simulation(30, 14);
    let msg = b"perf payload";
    let iter: u32 = 20;
    let start = Instant::now();
    for _ in 0..iter {
        let _ = run_threshold_blind_sign(&finalised, 14, SIGN_SESSION, msg);
    }
    let elapsed = start.elapsed();
    eprintln!(
        "[perf] threshold_blind_sign (n=30, t=14): {:>10} ns/op  ({} iter, {:>5} ms total)",
        elapsed.as_nanos() / u128::from(iter),
        iter,
        elapsed.as_millis()
    );
}
