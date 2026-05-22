//! DKG ceremony integration tests (spec §3.4).
//!
//! Exercises the joint-Feldman-Pedersen DKG end-to-end via a single-
//! process simulation of `n` validators. The happy-path simulation
//! verifies:
//!
//! - All parties agree on the joint public key.
//! - The joint secret is reconstructible from any `t` final shares
//!   via Lagrange interpolation.
//! - Bad POKs and tampered shares are rejected at finalisation time.

#![allow(clippy::similar_names, clippy::unreadable_literal)]

use std::time::Instant;

use borsh::{from_slice, to_vec};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, scalar::Scalar,
};
use rand::rngs::OsRng;
use tardus_mint::{
    dkg::{dkg_finalize, dkg_start, verify_round1_pok, DkgFinalised, PeerContribution},
    error::Error,
    transcript::CeremonyId,
    vss::{h_generator, VssParameters, VssShare},
};

const CEREMONY_ID: CeremonyId = CeremonyId::from_bytes([0xAA; 16]);

// =====================================================================
// Simulation helper
// =====================================================================

/// Run a full single-process DKG simulation with `n` parties at
/// threshold `t`. Each party performs `dkg_start`, then each party
/// finalises against the broadcasts and shares from all peers.
fn run_dkg_simulation(n: u16, t: u16) -> Vec<DkgFinalised> {
    let mut rng = OsRng;
    let h = h_generator();
    let params = VssParameters::new(n, t).expect("valid params");

    // Each party generates its contribution.
    let outputs: Vec<_> = (1..=n)
        .map(|i| dkg_start(CEREMONY_ID, i, params, &h, &mut rng).expect("dkg_start"))
        .collect();

    // Each party finalises.
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
        let final_ = dkg_finalize(&outputs[i_idx], &received, &h).expect("dkg_finalize");
        finalisations.push(final_);
    }
    finalisations
}

/// Reconstruct a polynomial's value at `x=0` from a subset of
/// `(index, share)` evaluations via Lagrange interpolation.
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
            .expect("final share is canonical by construction");
        reconstructed += lambda * share;
    }
    reconstructed
}

// =====================================================================
// Happy-path correctness
// =====================================================================

#[test]
fn dkg_n4_t3_all_parties_agree_on_joint_pk() {
    let finalised = run_dkg_simulation(4, 3);
    let joint_pk_0 = finalised[0].joint_pk.to_bytes();
    for f in &finalised[1..] {
        assert_eq!(
            f.joint_pk.to_bytes(),
            joint_pk_0,
            "all parties must agree on joint_pk"
        );
    }
}

#[test]
fn dkg_n4_t3_qual_contains_all_indices() {
    let finalised = run_dkg_simulation(4, 3);
    for f in &finalised {
        assert_eq!(f.qual, vec![1, 2, 3, 4], "qual must be 1..=n in happy path");
    }
}

#[test]
fn dkg_n4_t3_lagrange_recovers_joint_secret() {
    let finalised = run_dkg_simulation(4, 3);
    let joint_pk_bytes = finalised[0].joint_pk.to_bytes();
    let joint_pk_pt = CompressedEdwardsY(joint_pk_bytes).decompress().unwrap();

    // Use first t=3 finalisations.
    let subset: Vec<&DkgFinalised> = finalised.iter().take(3).collect();
    let reconstructed = lagrange_reconstruct(&subset);
    let recovered_pk = reconstructed * ED25519_BASEPOINT_POINT;

    assert_eq!(
        recovered_pk, joint_pk_pt,
        "Lagrange reconstruction of t shares must recover the joint secret"
    );
}

#[test]
fn dkg_n4_t3_lagrange_works_with_any_t_subset() {
    let finalised = run_dkg_simulation(4, 3);
    let joint_pk_pt = CompressedEdwardsY(finalised[0].joint_pk.to_bytes())
        .decompress()
        .unwrap();

    // Try three different t-subsets: {1,2,3}, {2,3,4}, {1,3,4}.
    let subset_indices: [&[usize]; 3] = [&[0, 1, 2], &[1, 2, 3], &[0, 2, 3]];
    for indices in &subset_indices {
        let subset: Vec<&DkgFinalised> = indices.iter().map(|i| &finalised[*i]).collect();
        let reconstructed = lagrange_reconstruct(&subset);
        let recovered_pk = reconstructed * ED25519_BASEPOINT_POINT;
        assert_eq!(
            recovered_pk, joint_pk_pt,
            "Lagrange reconstruction must work on any t-subset"
        );
    }
}

// =====================================================================
// Failure-mode tests
// =====================================================================

#[test]
fn dkg_bad_pok_rejected_at_verify() {
    let mut rng = OsRng;
    let h = h_generator();
    let params = VssParameters::new(4, 3).unwrap();
    let mut out = dkg_start(CEREMONY_ID, 1, params, &h, &mut rng).unwrap();

    // Flip a bit in the POK signature's `s` scalar.
    out.broadcast.pok.s[0] ^= 0x01;

    match verify_round1_pok(&out.broadcast) {
        Err(Error::PokInvalid) => {}
        other => panic!("expected PokInvalid, got {other:?}"),
    }
}

#[test]
fn dkg_bad_pok_rejected_at_finalize() {
    let mut rng = OsRng;
    let h = h_generator();
    let params = VssParameters::new(4, 3).unwrap();
    let mut outputs: Vec<_> = (1..=4u16)
        .map(|i| dkg_start(CEREMONY_ID, i, params, &h, &mut rng).unwrap())
        .collect();

    // Corrupt party 2's POK.
    outputs[1].broadcast.pok.s[0] ^= 0x01;

    // Party 1 collects contributions and tries to finalise.
    let received: Vec<PeerContribution> = (2..=4u16)
        .map(|k| {
            let k_idx = (k - 1) as usize;
            PeerContribution {
                broadcast: outputs[k_idx].broadcast.clone(),
                share_for_me: outputs[k_idx].shares[0].clone(),
            }
        })
        .collect();

    match dkg_finalize(&outputs[0], &received, &h) {
        Err(Error::PokInvalid) => {}
        other => panic!("expected PokInvalid at finalize, got {other:?}"),
    }
}

#[test]
fn dkg_tampered_share_rejected_at_finalize() {
    let mut rng = OsRng;
    let h = h_generator();
    let params = VssParameters::new(4, 3).unwrap();
    let outputs: Vec<_> = (1..=4u16)
        .map(|i| dkg_start(CEREMONY_ID, i, params, &h, &mut rng).unwrap())
        .collect();

    // Party 1's received shares from peers 2, 3, 4. Tamper the share from peer 2.
    let mut received: Vec<PeerContribution> = (2..=4u16)
        .map(|k| {
            let k_idx = (k - 1) as usize;
            PeerContribution {
                broadcast: outputs[k_idx].broadcast.clone(),
                share_for_me: outputs[k_idx].shares[0].clone(),
            }
        })
        .collect();

    // Tamper via borsh roundtrip: flip the low bit of f_share.
    let bytes = to_vec(&received[0].share_for_me).unwrap();
    let mut new_bytes = bytes;
    new_bytes[2] ^= 0x01;
    received[0].share_for_me = from_slice::<VssShare>(&new_bytes).expect("borsh deserialise");

    match dkg_finalize(&outputs[0], &received, &h) {
        Err(Error::VssShareInvalid) => {}
        other => panic!("expected VssShareInvalid, got {other:?}"),
    }
}

#[test]
fn dkg_insufficient_messages_rejected() {
    let mut rng = OsRng;
    let h = h_generator();
    let params = VssParameters::new(4, 3).unwrap();
    let outputs: Vec<_> = (1..=4u16)
        .map(|i| dkg_start(CEREMONY_ID, i, params, &h, &mut rng).unwrap())
        .collect();

    // Only 2 received instead of n-1 = 3.
    let received: Vec<PeerContribution> = (2..=3u16)
        .map(|k| {
            let k_idx = (k - 1) as usize;
            PeerContribution {
                broadcast: outputs[k_idx].broadcast.clone(),
                share_for_me: outputs[k_idx].shares[0].clone(),
            }
        })
        .collect();

    match dkg_finalize(&outputs[0], &received, &h) {
        Err(Error::InsufficientMessages) => {}
        other => panic!("expected InsufficientMessages, got {other:?}"),
    }
}

#[test]
fn dkg_duplicate_peer_index_rejected() {
    let mut rng = OsRng;
    let h = h_generator();
    let params = VssParameters::new(4, 3).unwrap();
    let outputs: Vec<_> = (1..=4u16)
        .map(|i| dkg_start(CEREMONY_ID, i, params, &h, &mut rng).unwrap())
        .collect();

    // Build received with peer 2 appearing twice (and peer 3 missing).
    let received: Vec<PeerContribution> = vec![
        PeerContribution {
            broadcast: outputs[1].broadcast.clone(),
            share_for_me: outputs[1].shares[0].clone(),
        },
        PeerContribution {
            broadcast: outputs[1].broadcast.clone(),
            share_for_me: outputs[1].shares[0].clone(),
        },
        PeerContribution {
            broadcast: outputs[3].broadcast.clone(),
            share_for_me: outputs[3].shares[0].clone(),
        },
    ];

    match dkg_finalize(&outputs[0], &received, &h) {
        Err(Error::DuplicateParticipant) => {}
        other => panic!("expected DuplicateParticipant, got {other:?}"),
    }
}

#[test]
fn dkg_self_index_in_received_rejected() {
    let mut rng = OsRng;
    let h = h_generator();
    let params = VssParameters::new(4, 3).unwrap();
    let outputs: Vec<_> = (1..=4u16)
        .map(|i| dkg_start(CEREMONY_ID, i, params, &h, &mut rng).unwrap())
        .collect();

    // Build received that includes a "peer" with same from_index as self.
    let mut bogus = outputs[0].broadcast.clone();
    bogus.from_index = 1; // collides with self
    let received: Vec<PeerContribution> = vec![
        PeerContribution {
            broadcast: bogus,
            share_for_me: outputs[1].shares[0].clone(),
        },
        PeerContribution {
            broadcast: outputs[2].broadcast.clone(),
            share_for_me: outputs[2].shares[0].clone(),
        },
        PeerContribution {
            broadcast: outputs[3].broadcast.clone(),
            share_for_me: outputs[3].shares[0].clone(),
        },
    ];

    match dkg_finalize(&outputs[0], &received, &h) {
        Err(Error::DomainMismatch) => {}
        other => panic!("expected DomainMismatch (self-collision), got {other:?}"),
    }
}

// =====================================================================
// Performance
// =====================================================================

#[test]
fn perf_dkg_start_n30_t14() {
    let mut rng = OsRng;
    let h = h_generator();
    let params = VssParameters::new(30, 14).unwrap();
    let iter: u32 = 50;

    let start = Instant::now();
    for _ in 0..iter {
        let _ = dkg_start(CEREMONY_ID, 1, params, &h, &mut rng).unwrap();
    }
    let elapsed = start.elapsed();
    let ns_per_op = elapsed.as_nanos() / u128::from(iter);
    eprintln!(
        "[perf] dkg_start (n=30, t=14):       {:>10} ns/op ({} iter, {:>5} ms total)",
        ns_per_op,
        iter,
        elapsed.as_millis()
    );
}

#[test]
fn perf_full_dkg_n30_t14() {
    let iter: u32 = 5;
    let start = Instant::now();
    for _ in 0..iter {
        let _ = run_dkg_simulation(30, 14);
    }
    let elapsed = start.elapsed();
    let ns_per_op = elapsed.as_nanos() / u128::from(iter);
    eprintln!(
        "[perf] full DKG sim (n=30, t=14):    {:>10} ns/op ({} iter, {:>5} ms total)",
        ns_per_op,
        iter,
        elapsed.as_millis()
    );
}
