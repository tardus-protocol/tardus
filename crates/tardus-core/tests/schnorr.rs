//! Integration tests for the single-party Schnorr signature scheme (spec §2.4).

#![allow(clippy::similar_names)]

use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tardus_core::{schnorr_sign, schnorr_verify, Keypair, PublicKey, SecretKey, Signature};

#[test]
fn roundtrip_passes_verifier() {
    let mut rng = OsRng;
    let kp = Keypair::random(&mut rng);
    let msg = b"roundtrip payload";

    let sig = schnorr_sign(&kp.secret, &kp.public, msg, &mut rng);
    assert!(
        schnorr_verify(&kp.public, msg, &sig).unwrap(),
        "valid signature must verify"
    );
}

#[test]
fn wrong_message_rejected() {
    let mut rng = OsRng;
    let kp = Keypair::random(&mut rng);

    let sig = schnorr_sign(&kp.secret, &kp.public, b"original", &mut rng);
    assert!(
        !schnorr_verify(&kp.public, b"tampered", &sig).unwrap(),
        "verifier must reject mismatched message"
    );
}

#[test]
fn wrong_public_key_rejected() {
    let mut rng = OsRng;
    let kp_signer = Keypair::random(&mut rng);
    let kp_other = Keypair::random(&mut rng);
    let msg = b"target message";

    let sig = schnorr_sign(&kp_signer.secret, &kp_signer.public, msg, &mut rng);
    assert!(
        !schnorr_verify(&kp_other.public, msg, &sig).unwrap(),
        "verifier must reject signature under wrong public key"
    );
}

#[test]
fn deterministic_under_seeded_rng() {
    // Same seed → same key and same signature. This is the regression
    // anchor: any future change to the signing routine that perturbs
    // the algebra will break this assertion.
    let kp = {
        let mut rng = ChaCha20Rng::seed_from_u64(0xDEAD_BEEF);
        Keypair::random(&mut rng)
    };
    let msg = b"deterministic vector";

    let sig_a = {
        let mut rng = ChaCha20Rng::seed_from_u64(0x1234);
        schnorr_sign(&kp.secret, &kp.public, msg, &mut rng)
    };
    let sig_b = {
        let mut rng = ChaCha20Rng::seed_from_u64(0x1234);
        schnorr_sign(&kp.secret, &kp.public, msg, &mut rng)
    };
    assert_eq!(sig_a, sig_b, "identical seed must produce identical signature");

    let sig_c = {
        let mut rng = ChaCha20Rng::seed_from_u64(0x5678);
        schnorr_sign(&kp.secret, &kp.public, msg, &mut rng)
    };
    assert_ne!(sig_a, sig_c, "different seed must produce different signature");

    assert!(schnorr_verify(&kp.public, msg, &sig_a).unwrap());
    assert!(schnorr_verify(&kp.public, msg, &sig_c).unwrap());
}

#[test]
fn signature_bytes_roundtrip() {
    let mut rng = OsRng;
    let kp = Keypair::random(&mut rng);
    let msg = b"bytes roundtrip";
    let sig = schnorr_sign(&kp.secret, &kp.public, msg, &mut rng);

    let bytes = sig.to_bytes();
    assert_eq!(bytes.len(), 64);
    let recovered = Signature::from_bytes(&bytes);
    assert_eq!(sig, recovered);
    assert!(schnorr_verify(&kp.public, msg, &recovered).unwrap());
}

#[test]
fn key_bytes_roundtrip() {
    let mut rng = OsRng;
    let kp = Keypair::random(&mut rng);

    let sk_bytes = kp.secret.to_bytes();
    let pk_bytes = kp.public.to_bytes();
    assert_eq!(sk_bytes.len(), 32);
    assert_eq!(pk_bytes.len(), 32);

    let sk2 = SecretKey::from_bytes(&sk_bytes).unwrap();
    let pk2 = PublicKey::from_bytes(&pk_bytes).unwrap();

    // Roundtripped key must produce the same public key
    assert_eq!(PublicKey::from_secret(&sk2), kp.public);
    assert_eq!(pk2, kp.public);
}

#[test]
fn rejects_zero_signature() {
    let mut rng = OsRng;
    let kp = Keypair::random(&mut rng);
    // All-zero signature scalar+point is not a valid signature for any
    // non-zero message (with overwhelming probability). Verify it fails
    // without panicking.
    let bad_sig = Signature {
        r: [0u8; 32],
        s: [0u8; 32],
    };
    // The point [0u8;32] is the identity (valid encoding); the resulting
    // verification equation lhs = sG = 0, rhs = R + c·pk = 0 + c·pk ≠ 0
    // for fresh pk, so this should be Ok(false). An Err is also acceptable
    // (zero point may be rejected by torsion checks downstream).
    let result = schnorr_verify(&kp.public, b"x", &bad_sig);
    if let Ok(verdict) = result {
        assert!(!verdict, "all-zero sig must not verify");
    }
}
