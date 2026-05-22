//! Unit tests for Coin model and HKDF-based coin secret derivation
//! (spec §4.2, §4.4).

#![allow(clippy::similar_names, clippy::unreadable_literal)]

use std::time::Instant;

use curve25519_dalek::scalar::Scalar;
use rand::{rngs::OsRng, RngCore};
use tardus_core::{schnorr_sign, Keypair, PublicKey, SecretKey, Signature};
use tardus_refresh::{
    coin::{Coin, NULLIFIER_DOMAIN},
    derivation::{derive_coin_secret, COIN_SECRET_INFO, REFRESH_DOMAIN},
    error::Error,
};

// =====================================================================
// Derivation tests
// =====================================================================

#[test]
fn derivation_deterministic() {
    let seed = [0x42u8; 32];
    let s1 = derive_coin_secret(&seed);
    let s2 = derive_coin_secret(&seed);
    assert_eq!(s1, s2, "same seed must yield same scalar");
}

#[test]
fn derivation_different_seeds_yield_different_secrets() {
    let s1 = derive_coin_secret(&[0x01u8; 32]);
    let s2 = derive_coin_secret(&[0x02u8; 32]);
    assert_ne!(s1, s2, "different seeds must yield different scalars");
}

#[test]
fn derivation_produces_canonical_scalar() {
    let seed = [0xAAu8; 32];
    let s = derive_coin_secret(&seed);
    // Roundtrip via canonical-bytes check
    let bytes = s.to_bytes();
    let recovered = Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
        .expect("derived scalar must be canonical");
    assert_eq!(recovered, s);
}

#[test]
fn derivation_constants_are_what_spec_says() {
    assert_eq!(REFRESH_DOMAIN, b"TARDUS-refresh-v1");
    assert_eq!(COIN_SECRET_INFO, b"coin-secret");
}

// =====================================================================
// Coin tests
// =====================================================================

/// Helper: construct a valid coin by self-signing (single-party Schnorr
/// stands in for the threshold mint signature in this unit test).
fn make_valid_coin(rng: &mut OsRng) -> (PublicKey, Coin) {
    // The "mint" — a single Keypair stands in for joint_pk
    let mint = Keypair::random(rng);

    // The coin owner generates their secret
    let secret_seed = {
        let mut s = [0u8; 32];
        rng.fill_bytes(&mut s);
        s
    };
    let x = derive_coin_secret(&secret_seed);
    let sk = SecretKey::from_bytes(&x.to_bytes()).expect("canonical");
    let pk = PublicKey::from_secret(&sk);
    let cp_bytes = pk.to_bytes();

    // Mint signs the coin's pubkey
    let sig = schnorr_sign(&mint.secret, &mint.public, &cp_bytes, rng);

    let coin = Coin::new(sk, cp_bytes, sig).expect("construction with consistent inputs");
    (mint.public, coin)
}

#[test]
fn coin_construction_with_consistent_inputs() {
    let mut rng = OsRng;
    let (mint_pk, coin) = make_valid_coin(&mut rng);
    // Coin verifies against the mint's pk
    assert!(coin.verify(&mint_pk).unwrap(), "valid coin must verify");
}

#[test]
fn coin_construction_rejects_mismatched_pubkey() {
    let mut rng = OsRng;
    let mint = Keypair::random(&mut rng);

    let sk_a = SecretKey::random(&mut rng);
    let sk_b = SecretKey::random(&mut rng);
    let pk_b = PublicKey::from_secret(&sk_b);
    // Sign pk_b but try to construct a coin claiming sk_a owns pk_b
    let sig = schnorr_sign(&mint.secret, &mint.public, &pk_b.to_bytes(), &mut rng);

    match Coin::new(sk_a, pk_b.to_bytes(), sig) {
        Err(Error::CoinPubkeyMismatch) => {}
        other => panic!("expected CoinPubkeyMismatch, got {other:?}"),
    }
}

#[test]
fn coin_verify_fails_under_wrong_mint() {
    let mut rng = OsRng;
    let (_mint_pk, coin) = make_valid_coin(&mut rng);
    let other_mint = Keypair::random(&mut rng);
    assert!(
        !coin.verify(&other_mint.public).unwrap(),
        "coin must not verify under a different mint pk"
    );
}

#[test]
fn coin_nullifier_is_deterministic() {
    let mut rng = OsRng;
    let (_, coin) = make_valid_coin(&mut rng);
    let n1 = coin.nullifier();
    let n2 = coin.nullifier();
    assert_eq!(n1, n2, "nullifier must be deterministic for a given coin");
}

#[test]
fn coin_nullifier_uses_domain_separator() {
    // Sanity check: nullifier is NOT just hash(pubkey), it includes a domain prefix.
    use sha2::{Digest, Sha256};
    let mut rng = OsRng;
    let (_, coin) = make_valid_coin(&mut rng);
    let actual = coin.nullifier();

    // What you'd get without domain separator:
    let mut hasher = Sha256::new();
    hasher.update(coin.pubkey_bytes());
    let naive: [u8; 32] = hasher.finalize().into();

    assert_ne!(
        actual, naive,
        "nullifier MUST include a domain separator to avoid collision with bare-hash schemes"
    );

    // The spec constant is what we use
    assert_eq!(NULLIFIER_DOMAIN, b"TARDUS-nullifier-v1");
}

#[test]
fn different_coins_have_different_nullifiers() {
    let mut rng = OsRng;
    let (_, coin1) = make_valid_coin(&mut rng);
    let (_, coin2) = make_valid_coin(&mut rng);
    assert_ne!(coin1.nullifier(), coin2.nullifier());
}

// =====================================================================
// Performance
// =====================================================================

#[test]
fn perf_derive_coin_secret() {
    let seed = [0xCCu8; 32];
    let iter: u32 = 10_000;
    let start = Instant::now();
    for _ in 0..iter {
        let _ = derive_coin_secret(&seed);
    }
    let elapsed = start.elapsed();
    eprintln!(
        "[perf] derive_coin_secret:        {:>8} ns/op  ({} iter, {:>4} ms total)",
        elapsed.as_nanos() / u128::from(iter),
        iter,
        elapsed.as_millis()
    );
}

#[test]
fn perf_coin_nullifier() {
    let mut rng = OsRng;
    let (_, coin) = make_valid_coin(&mut rng);
    let iter: u32 = 10_000;
    let start = Instant::now();
    for _ in 0..iter {
        let _ = coin.nullifier();
    }
    let elapsed = start.elapsed();
    eprintln!(
        "[perf] coin_nullifier:            {:>8} ns/op  ({} iter, {:>4} ms total)",
        elapsed.as_nanos() / u128::from(iter),
        iter,
        elapsed.as_millis()
    );
}

// Silence unused-import warnings until the protocol layer
// reaches Phase 1.3c. These imports anchor the public surface
// against compile errors.
#[allow(dead_code)]
fn _link_anchors() {
    let _: Option<Signature> = None;
}
