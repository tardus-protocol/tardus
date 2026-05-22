//! Integration tests for Pedersen Verifiable Secret Sharing (spec §2.6, §3.4.2).

#![allow(clippy::similar_names, clippy::unreadable_literal)]

use std::time::Instant;

use borsh::{from_slice, to_vec};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tardus_mint::{
    error::Error,
    vss::{deal, h_generator, verify_share, VssCommitments, VssParameters, VssShare},
};

/// Reconstruct the f-polynomial scalar from a share's public byte view.
fn share_f_scalar(share: &VssShare) -> Scalar {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(share.f_share_bytes()))
        .expect("share f_share_bytes must always be canonical")
}

// =====================================================================
// h_generator
// =====================================================================

#[test]
fn h_generator_is_deterministic() {
    let h1 = h_generator();
    let h2 = h_generator();
    assert_eq!(h1, h2, "h_generator must be reproducible across calls");
}

#[test]
fn h_generator_is_not_basepoint() {
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    let h = h_generator();
    assert_ne!(h, ED25519_BASEPOINT_POINT, "H must not equal G");
}

// =====================================================================
// VssParameters
// =====================================================================

#[test]
fn parameters_invalid_rejected() {
    assert!(matches!(
        VssParameters::new(30, 0),
        Err(Error::InvalidSigningSet)
    ));
    assert!(matches!(
        VssParameters::new(30, 31),
        Err(Error::InvalidSigningSet)
    ));
}

#[test]
fn parameters_valid_accepted() {
    assert!(VssParameters::new(30, 1).is_ok());
    assert!(VssParameters::new(30, 14).is_ok());
    assert!(VssParameters::new(30, 30).is_ok());
    assert!(VssParameters::new(1, 1).is_ok());
}

// =====================================================================
// deal / verify_share
// =====================================================================

#[test]
fn deal_produces_n_shares() {
    let mut rng = OsRng;
    let h = h_generator();
    let params = VssParameters::new(30, 14).unwrap();
    let secret = Scalar::random(&mut rng);
    let (commitments, _feldman, shares) = deal(&secret, params, &h, &mut rng);

    assert_eq!(shares.len(), 30, "must produce n=30 shares");
    assert_eq!(commitments.t(), 14, "must produce t=14 commitments");
    for (i, share) in shares.iter().enumerate() {
        assert_eq!(usize::from(share.index()), i + 1, "indices must be 1..=n");
    }
}

#[test]
fn each_share_verifies() {
    let mut rng = OsRng;
    let h = h_generator();
    let params = VssParameters::new(30, 14).unwrap();
    let secret = Scalar::random(&mut rng);
    let (commitments, _feldman, shares) = deal(&secret, params, &h, &mut rng);

    for share in &shares {
        verify_share(share, &commitments, &h)
            .unwrap_or_else(|_| panic!("share {} must verify", share.index()));
    }
}

#[test]
fn tampered_share_rejected() {
    let mut rng = OsRng;
    let h = h_generator();
    let params = VssParameters::new(30, 14).unwrap();
    let secret = Scalar::random(&mut rng);
    let (commitments, _feldman, shares) = deal(&secret, params, &h, &mut rng);

    // Serialise the first share, flip a bit in the f_share scalar
    // (offset 2..34 in the borsh layout: u16 index, then 32-byte f, 32-byte g)
    // and deserialise as a tampered share.
    let mut bytes = to_vec(&shares[0]).expect("borsh serialise");
    bytes[2] ^= 0x01; // flip low bit of f_share[0]
    let tampered: VssShare = from_slice(&bytes).expect("tampered share must still parse");

    match verify_share(&tampered, &commitments, &h) {
        Err(Error::VssShareInvalid) => {}
        other => panic!("expected VssShareInvalid, got {other:?}"),
    }
}

#[test]
fn verify_share_zero_index_rejected() {
    let mut rng = OsRng;
    let h = h_generator();
    let params = VssParameters::new(30, 14).unwrap();
    let secret = Scalar::random(&mut rng);
    let (commitments, _feldman, shares) = deal(&secret, params, &h, &mut rng);

    // Forge a share with index 0
    let mut bytes = to_vec(&shares[0]).expect("borsh serialise");
    bytes[0] = 0;
    bytes[1] = 0;
    let zero_idx: VssShare = from_slice(&bytes).expect("borsh deserialise");

    match verify_share(&zero_idx, &commitments, &h) {
        Err(Error::InvalidSigningSet) => {}
        other => panic!("expected InvalidSigningSet, got {other:?}"),
    }
}

// =====================================================================
// Threshold property: Lagrange reconstruction
// =====================================================================

#[test]
fn lagrange_reconstruction_recovers_secret() {
    let mut rng = OsRng;
    let h = h_generator();
    let params = VssParameters::new(30, 14).unwrap();
    let secret = Scalar::random(&mut rng);
    let (_commitments, _feldman, shares) = deal(&secret, params, &h, &mut rng);

    // Take any t=14 shares.
    let subset: Vec<&VssShare> = shares.iter().take(14).collect();

    // Lagrange reconstruction at x = 0:
    //   f(0) = Σ_i λ_i(0) · f(j_i)
    // where λ_i(0) = Π_{k≠i} (-j_k) / (j_i - j_k).
    let mut reconstructed = Scalar::ZERO;
    for share_i in &subset {
        let i_scalar = Scalar::from(u64::from(share_i.index()));
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for share_k in &subset {
            if share_k.index() == share_i.index() {
                continue;
            }
            let k_scalar = Scalar::from(u64::from(share_k.index()));
            num *= -k_scalar;
            den *= i_scalar - k_scalar;
        }
        let lambda = num * den.invert();
        reconstructed += lambda * share_f_scalar(share_i);
    }

    assert_eq!(
        reconstructed, secret,
        "Lagrange reconstruction from t shares must recover the dealt secret"
    );
}

#[test]
fn lagrange_reconstruction_works_with_any_t_subset() {
    let mut rng = OsRng;
    let h = h_generator();
    let params = VssParameters::new(30, 14).unwrap();
    let secret = Scalar::random(&mut rng);
    let (_commitments, _feldman, shares) = deal(&secret, params, &h, &mut rng);

    // Try several disjoint t-subsets.
    let subsets: [Vec<usize>; 3] = [
        (0..14).collect(),
        (16..30).collect(),
        vec![0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26],
    ];

    for subset_idx in &subsets {
        let subset: Vec<&VssShare> = subset_idx.iter().map(|i| &shares[*i]).collect();
        let mut reconstructed = Scalar::ZERO;
        for share_i in &subset {
            let i_scalar = Scalar::from(u64::from(share_i.index()));
            let mut num = Scalar::ONE;
            let mut den = Scalar::ONE;
            for share_k in &subset {
                if share_k.index() == share_i.index() {
                    continue;
                }
                let k_scalar = Scalar::from(u64::from(share_k.index()));
                num *= -k_scalar;
                den *= i_scalar - k_scalar;
            }
            let lambda = num * den.invert();
            reconstructed += lambda * share_f_scalar(share_i);
        }
        assert_eq!(
            reconstructed, secret,
            "Lagrange reconstruction must work on any t-subset"
        );
    }
}

// =====================================================================
// Determinism
// =====================================================================

#[test]
fn deal_deterministic_with_seeded_rng() {
    let h = h_generator();
    let params = VssParameters::new(30, 14).unwrap();

    let (c1, _f1, s1) = {
        let mut rng = ChaCha20Rng::seed_from_u64(0xC0FFEE);
        let secret = Scalar::random(&mut rng);
        deal(&secret, params, &h, &mut rng)
    };
    let (c2, _f2, s2) = {
        let mut rng = ChaCha20Rng::seed_from_u64(0xC0FFEE);
        let secret = Scalar::random(&mut rng);
        deal(&secret, params, &h, &mut rng)
    };

    assert_eq!(c1, c2, "commitments must be identical under same seed");
    assert_eq!(s1.len(), s2.len());
    for (a, b) in s1.iter().zip(s2.iter()) {
        assert_eq!(a.index(), b.index());
        assert_eq!(a.f_share_bytes(), b.f_share_bytes());
        assert_eq!(a.g_share_bytes(), b.g_share_bytes());
    }
}

// =====================================================================
// Borsh roundtrips
// =====================================================================

#[test]
fn commitments_borsh_roundtrip() {
    let mut rng = OsRng;
    let h = h_generator();
    let params = VssParameters::new(30, 14).unwrap();
    let secret = Scalar::random(&mut rng);
    let (commitments, _feldman, _shares) = deal(&secret, params, &h, &mut rng);

    let bytes = to_vec(&commitments).expect("borsh serialise commitments");
    let recovered: VssCommitments = from_slice(&bytes).expect("borsh deserialise");
    assert_eq!(commitments, recovered);
}

#[test]
fn share_borsh_roundtrip() {
    let mut rng = OsRng;
    let h = h_generator();
    let params = VssParameters::new(30, 14).unwrap();
    let secret = Scalar::random(&mut rng);
    let (_c, _feldman, shares) = deal(&secret, params, &h, &mut rng);

    let bytes = to_vec(&shares[5]).expect("borsh serialise share");
    let recovered: VssShare = from_slice(&bytes).expect("borsh deserialise");
    assert_eq!(recovered.index(), shares[5].index());
    assert_eq!(recovered.f_share_bytes(), shares[5].f_share_bytes());
    assert_eq!(recovered.g_share_bytes(), shares[5].g_share_bytes());
}

// =====================================================================
// Performance
// =====================================================================

const DEAL_ITERATIONS: u32 = 100;
const VERIFY_ITERATIONS: u32 = 1_000;

#[test]
fn perf_vss_deal_n30_t14() {
    let mut rng = OsRng;
    let h = h_generator();
    let params = VssParameters::new(30, 14).unwrap();

    let start = Instant::now();
    for _ in 0..DEAL_ITERATIONS {
        let secret = Scalar::random(&mut rng);
        let _ = deal(&secret, params, &h, &mut rng);
    }
    let elapsed = start.elapsed();
    let ns_per_op = elapsed.as_nanos() / u128::from(DEAL_ITERATIONS);
    eprintln!(
        "[perf] vss_deal (n=30, t=14):    {:>10} ns/op   ({} iter, {:>6} ms total)",
        ns_per_op,
        DEAL_ITERATIONS,
        elapsed.as_millis()
    );
}

#[test]
fn perf_vss_verify_share_t14() {
    let mut rng = OsRng;
    let h = h_generator();
    let params = VssParameters::new(30, 14).unwrap();
    let secret = Scalar::random(&mut rng);
    let (commitments, _feldman, shares) = deal(&secret, params, &h, &mut rng);
    let share = &shares[7];

    let start = Instant::now();
    for _ in 0..VERIFY_ITERATIONS {
        verify_share(share, &commitments, &h).unwrap();
    }
    let elapsed = start.elapsed();
    let ns_per_op = elapsed.as_nanos() / u128::from(VERIFY_ITERATIONS);
    eprintln!(
        "[perf] vss_verify_share (t=14):  {:>10} ns/op   ({} iter, {:>6} ms total)",
        ns_per_op,
        VERIFY_ITERATIONS,
        elapsed.as_millis()
    );
}

#[test]
fn perf_h_generator() {
    let iterations: u32 = 100;
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = h_generator();
    }
    let elapsed = start.elapsed();
    let ns_per_op = elapsed.as_nanos() / u128::from(iterations);
    eprintln!(
        "[perf] h_generator:              {:>10} ns/op   ({} iter, {:>6} ms total)",
        ns_per_op,
        iterations,
        elapsed.as_millis()
    );
}
