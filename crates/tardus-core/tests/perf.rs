//! Microbenchmark-style timing tests for tardus-core.
//!
//! Run with `cargo test -p tardus-core --release -- --nocapture` to
//! observe ns/op numbers. These are not full Criterion benches yet;
//! a `benches/` directory with proper Criterion harnesses is added
//! when CU-budget analysis begins (Phase 1.4).

use rand::rngs::OsRng;
use std::time::Instant;
use tardus_core::{
    blind_request, issue_round1, issue_round2, schnorr_sign, schnorr_verify, unblind, Keypair,
};

const ITERATIONS: u32 = 1_000;

fn ns_per_op(elapsed_nanos: u128, iterations: u32) -> u128 {
    elapsed_nanos / u128::from(iterations)
}

#[test]
fn perf_schnorr_sign() {
    let mut rng = OsRng;
    let kp = Keypair::random(&mut rng);
    let msg = b"benchmark message payload xx";

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _sig = schnorr_sign(&kp.secret, &kp.public, msg, &mut rng);
    }
    let elapsed = start.elapsed();
    eprintln!(
        "[perf] schnorr_sign:          {:>8} ns/op   ({} iterations, {:>6} ms total)",
        ns_per_op(elapsed.as_nanos(), ITERATIONS),
        ITERATIONS,
        elapsed.as_millis()
    );
}

#[test]
fn perf_schnorr_verify() {
    let mut rng = OsRng;
    let kp = Keypair::random(&mut rng);
    let msg = b"benchmark message payload xx";
    let sig = schnorr_sign(&kp.secret, &kp.public, msg, &mut rng);

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ok = schnorr_verify(&kp.public, msg, &sig);
    }
    let elapsed = start.elapsed();
    eprintln!(
        "[perf] schnorr_verify:        {:>8} ns/op   ({} iterations, {:>6} ms total)",
        ns_per_op(elapsed.as_nanos(), ITERATIONS),
        ITERATIONS,
        elapsed.as_millis()
    );
}

#[test]
fn perf_blind_full_roundtrip() {
    let mut rng = OsRng;
    let kp = Keypair::random(&mut rng);
    let msg = b"benchmark blind payload xxxx";

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let (commit, ss) = issue_round1(&mut rng);
        let (challenge, us) = blind_request(&commit, &kp.public, msg, &mut rng).unwrap();
        let response = issue_round2(&ss, &challenge, &kp.secret).unwrap();
        let _sig = unblind(&us, &response).unwrap();
    }
    let elapsed = start.elapsed();
    eprintln!(
        "[perf] blind_full_roundtrip:  {:>8} ns/op   ({} iterations, {:>6} ms total)",
        ns_per_op(elapsed.as_nanos(), ITERATIONS),
        ITERATIONS,
        elapsed.as_millis()
    );
}
