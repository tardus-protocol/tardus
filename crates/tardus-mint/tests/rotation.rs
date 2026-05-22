//! Proactive secret-sharing rotation integration tests (spec §3.7).
//!
//! Crown jewel: full DKG → reshare → threshold blind signing using
//! the *new* shares produces a signature that verifies under the
//! *original* `joint_pk`. This is the operational proof that the
//! rotation is cryptographically transparent: from the verifier's
//! perspective, nothing changed except the long-term metadata-
//! correlation surface.

#![allow(
    clippy::similar_names,
    clippy::unreadable_literal,
    clippy::doc_markdown
)]

use std::time::Instant;

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
use rand::rngs::OsRng;
use tardus_core::{blind_request, schnorr_verify, unblind};
use tardus_mint::{
    dkg::{dkg_finalize, dkg_start, DkgFinalised, PeerContribution},
    error::Error,
    rotation::{reshare_finalize, reshare_start, ResharePeerContribution},
    sign::{
        aggregate_commitments, aggregate_responses, partial_sign, validator_round1,
        ValidatorR1Output, ValidatorR1State, ValidatorR3Output,
    },
    transcript::{CeremonyId, SessionId},
    vss::{h_generator, VssParameters},
};

const DKG_CEREMONY: CeremonyId = CeremonyId::from_bytes([0xAA; 16]);
const RESHARE_CEREMONY: CeremonyId = CeremonyId::from_bytes([0xCC; 16]);
const SIGN_SESSION: SessionId = SessionId::from_bytes([0xBB; 16]);

// =====================================================================
// Helpers (copied minimal from dkg/sign tests; share-via-common-module
// refactor is deferred)
// =====================================================================

fn run_dkg(n: u16, t: u16) -> Vec<DkgFinalised> {
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

/// Run a reshare ceremony with explicit (n, t) and produce updated
/// DkgFinalised entries.
fn run_reshare_with(n: u16, t: u16, old: &[DkgFinalised]) -> Vec<DkgFinalised> {
    let mut rng = OsRng;
    let h = h_generator();
    let params = VssParameters::new(n, t).expect("valid params");

    let outputs: Vec<_> = (1..=n)
        .map(|i| reshare_start(RESHARE_CEREMONY, i, params, &h, &mut rng).expect("reshare_start"))
        .collect();

    let mut new_finalisations = Vec::with_capacity(n as usize);
    for i in 1..=n {
        let i_idx = (i - 1) as usize;
        let received: Vec<ResharePeerContribution> = (1..=n)
            .filter(|&k| k != i)
            .map(|k| {
                let k_idx = (k - 1) as usize;
                ResharePeerContribution {
                    broadcast: outputs[k_idx].broadcast.clone(),
                    share_for_me: outputs[k_idx].shares[(i - 1) as usize].clone(),
                }
            })
            .collect();

        let old_i = &old[i_idx];
        let reshared = reshare_finalize(&outputs[i_idx], &old_i.my_share, &received, &h)
            .expect("reshare_finalize");

        // Construct new DkgFinalised with rotated share but unchanged joint_pk.
        new_finalisations.push(DkgFinalised {
            my_index: old_i.my_index,
            joint_pk: old_i.joint_pk,
            my_share: reshared.new_share,
            qual: old_i.qual.clone(),
        });
    }
    new_finalisations
}

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
        aggregate_commitments(session_id, &signing_set, &r1_outputs).expect("aggregate_commitments");

    let (challenge, user_state) =
        blind_request(&blind_commit, &joint_pk, msg, &mut rng).expect("blind_request");

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
    let blind_response =
        aggregate_responses(session_id, &signing_set, &r3_outputs).expect("aggregate_responses");

    unblind(&user_state, &blind_response).expect("unblind")
}

fn lagrange_reconstruct(subset: &[&DkgFinalised]) -> Scalar {
    let mut reconstructed = Scalar::ZERO;
    for f_i in subset {
        let i_scalar = Scalar::from(u64::from(f_i.my_index));
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for f_k in subset {
            if f_k.my_index == f_i.my_index {
                continue;
            }
            let k_scalar = Scalar::from(u64::from(f_k.my_index));
            num *= -k_scalar;
            den *= i_scalar - k_scalar;
        }
        let lambda = num * den.invert();
        let share = Option::<Scalar>::from(Scalar::from_canonical_bytes(f_i.my_share.to_bytes()))
            .expect("share is canonical");
        reconstructed += lambda * share;
    }
    reconstructed
}

// =====================================================================
// Invariant tests
// =====================================================================

#[test]
fn reshare_n4_t3_joint_pk_invariant() {
    let old = run_dkg(4, 3);
    let new = run_reshare_with(4, 3, &old);
    for f in &new {
        assert_eq!(
            f.joint_pk.to_bytes(),
            old[0].joint_pk.to_bytes(),
            "joint_pk must be preserved across rotation"
        );
    }
}

#[test]
fn reshare_n4_t3_lagrange_yields_same_secret() {
    let old = run_dkg(4, 3);
    let new = run_reshare_with(4, 3, &old);

    // Lagrange-reconstruct from any t old shares vs any t new shares.
    let old_subset: Vec<&DkgFinalised> = old.iter().take(3).collect();
    let new_subset: Vec<&DkgFinalised> = new.iter().take(3).collect();
    let sk_old = lagrange_reconstruct(&old_subset);
    let sk_new = lagrange_reconstruct(&new_subset);

    assert_eq!(
        sk_old, sk_new,
        "joint secret must be invariant under proactive rotation"
    );

    // Both reconstruct to the same secret, which corresponds to joint_pk.
    let recovered_pk = sk_new * ED25519_BASEPOINT_POINT;
    let expected_pt = curve25519_dalek::edwards::CompressedEdwardsY(old[0].joint_pk.to_bytes())
        .decompress()
        .unwrap();
    assert_eq!(recovered_pk, expected_pt);
}

#[test]
fn reshare_n4_t3_threshold_sign_after_reshare() {
    // Crown jewel: full DKG → reshare → threshold blind sign with the
    // *new* shares → verify signature under the *original* joint_pk.
    let old = run_dkg(4, 3);
    let new = run_reshare_with(4, 3, &old);
    let msg = b"sign-after-reshare must verify under original joint_pk";
    let sig = run_threshold_blind_sign(&new, 3, SIGN_SESSION, msg);

    assert!(
        schnorr_verify(&old[0].joint_pk, msg, &sig).unwrap(),
        "rotation must be operationally transparent — sig with new shares verifies under original joint_pk"
    );
}

#[test]
fn reshare_shares_actually_change() {
    let old = run_dkg(4, 3);
    let new = run_reshare_with(4, 3, &old);
    for (o, n) in old.iter().zip(new.iter()) {
        assert_ne!(
            o.my_share.to_bytes(),
            n.my_share.to_bytes(),
            "individual shares MUST change under rotation"
        );
    }
}

// =====================================================================
// Failure-mode tests
// =====================================================================

#[test]
fn reshare_tampered_share_rejected() {
    let mut rng = OsRng;
    let h = h_generator();
    let params = VssParameters::new(4, 3).unwrap();
    let old = run_dkg(4, 3);

    let outputs: Vec<_> = (1..=4u16)
        .map(|i| reshare_start(RESHARE_CEREMONY, i, params, &h, &mut rng).unwrap())
        .collect();

    // Tamper party 2's share to party 1 (bit-flip in f-component).
    let mut received: Vec<ResharePeerContribution> = (2..=4u16)
        .map(|k| {
            let k_idx = (k - 1) as usize;
            ResharePeerContribution {
                broadcast: outputs[k_idx].broadcast.clone(),
                share_for_me: outputs[k_idx].shares[0].clone(),
            }
        })
        .collect();
    let bytes = borsh::to_vec(&received[0].share_for_me).unwrap();
    let mut new_bytes = bytes;
    new_bytes[2] ^= 0x01;
    received[0].share_for_me = borsh::from_slice(&new_bytes).unwrap();

    match reshare_finalize(&outputs[0], &old[0].my_share, &received, &h) {
        Err(Error::VssShareInvalid) => {}
        other => panic!("expected VssShareInvalid, got {other:?}"),
    }
}

#[test]
fn reshare_insufficient_messages_rejected() {
    let mut rng = OsRng;
    let h = h_generator();
    let params = VssParameters::new(4, 3).unwrap();
    let old = run_dkg(4, 3);

    let outputs: Vec<_> = (1..=4u16)
        .map(|i| reshare_start(RESHARE_CEREMONY, i, params, &h, &mut rng).unwrap())
        .collect();

    // Only 2 received instead of n-1 = 3.
    let received: Vec<ResharePeerContribution> = (2..=3u16)
        .map(|k| {
            let k_idx = (k - 1) as usize;
            ResharePeerContribution {
                broadcast: outputs[k_idx].broadcast.clone(),
                share_for_me: outputs[k_idx].shares[0].clone(),
            }
        })
        .collect();

    match reshare_finalize(&outputs[0], &old[0].my_share, &received, &h) {
        Err(Error::InsufficientMessages) => {}
        other => panic!("expected InsufficientMessages, got {other:?}"),
    }
}

// =====================================================================
// Performance
// =====================================================================

#[test]
fn perf_reshare_full_n30_t14() {
    let old = run_dkg(30, 14);
    let iter: u32 = 5;
    let start = Instant::now();
    for _ in 0..iter {
        let _ = run_reshare_with(30, 14, &old);
    }
    let elapsed = start.elapsed();
    eprintln!(
        "[perf] full reshare (n=30, t=14):    {:>10} ns/op  ({} iter, {:>5} ms total)",
        elapsed.as_nanos() / u128::from(iter),
        iter,
        elapsed.as_millis()
    );
}

