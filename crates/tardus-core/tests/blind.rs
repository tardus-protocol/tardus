//! Integration tests for the Blind Schnorr signature scheme (spec §2.5).

#![allow(clippy::similar_names)]
//!
//! The protocol is exercised end-to-end; the key property verified is
//! that an unblinded signature produced through the blind issuance
//! protocol passes the *standard* Schnorr verifier under the issuing
//! public key.

use rand::rngs::OsRng;
use tardus_core::{
    blind_request, issue_round1, issue_round2, schnorr_verify, unblind, Keypair,
};

#[test]
fn blind_roundtrip_yields_valid_schnorr_signature() {
    let mut rng = OsRng;
    let kp = Keypair::random(&mut rng);
    let msg = b"blind payload v1";

    // Round 1 — signer commits.
    let (commit, signer_state) = issue_round1(&mut rng);

    // Round 2 — user blinds, computes challenge.
    let (challenge, user_state) =
        blind_request(&commit, &kp.public, msg, &mut rng).expect("blind_request");

    // Round 3 — signer responds.
    let response =
        issue_round2(&signer_state, &challenge, &kp.secret).expect("issue_round2");

    // Round 4 — user unblinds.
    let sig = unblind(&user_state, &response).expect("unblind");

    // The unblinded signature must verify under the issuer's public key
    // through the *standard* (non-blind) Schnorr verifier.
    assert!(
        schnorr_verify(&kp.public, msg, &sig).expect("verify"),
        "unblinded blind-issued signature must verify under the standard Schnorr verifier"
    );
}

#[test]
fn many_independent_blind_issuances() {
    // 200 independent blind issuances; each must yield a valid signature.
    // Failure of any single trial points to a soundness regression.
    let mut rng = OsRng;
    let kp = Keypair::random(&mut rng);

    for trial in 0..200_u32 {
        // 4-byte trial counter + 15-byte tag = 19-byte message
        let mut msg = [0u8; 19];
        msg[..4].copy_from_slice(&trial.to_le_bytes());
        msg[4..].copy_from_slice(b"-tardus-blind-x");

        let (commit, signer_state) = issue_round1(&mut rng);
        let (challenge, user_state) =
            blind_request(&commit, &kp.public, &msg, &mut rng).expect("blind_request");
        let response =
            issue_round2(&signer_state, &challenge, &kp.secret).expect("issue_round2");
        let sig = unblind(&user_state, &response).expect("unblind");

        assert!(
            schnorr_verify(&kp.public, &msg, &sig).expect("verify"),
            "trial {trial} produced an invalid signature"
        );
    }
}

#[test]
fn signer_view_differs_from_user_view() {
    // The signer sees only `R`, `c`, `s`. The user holds the unblinded
    // signature `(R', s')`. These must differ in both R and s
    // (because alpha, beta are uniform non-zero with overwhelming prob).
    let mut rng = OsRng;
    let kp = Keypair::random(&mut rng);
    let msg = b"signer-view-test";

    let (commit, signer_state) = issue_round1(&mut rng);
    let (challenge, user_state) =
        blind_request(&commit, &kp.public, msg, &mut rng).expect("blind_request");
    let response =
        issue_round2(&signer_state, &challenge, &kp.secret).expect("issue_round2");
    let sig = unblind(&user_state, &response).expect("unblind");

    assert_ne!(
        commit.r, sig.r,
        "blinded commitment R must differ from final R'"
    );
    assert_ne!(
        response.s, sig.s,
        "signer's blinded s must differ from final unblinded s'"
    );
    assert_ne!(
        challenge.c, sig.r,
        "signer-visible challenge c must not coincide with R' bytes"
    );
}

#[test]
fn distinct_messages_produce_distinct_outputs() {
    let mut rng = OsRng;
    let kp = Keypair::random(&mut rng);

    let make_sig = |msg: &[u8], rng: &mut OsRng| {
        let (commit, ss) = issue_round1(rng);
        let (challenge, us) = blind_request(&commit, &kp.public, msg, rng).unwrap();
        let response = issue_round2(&ss, &challenge, &kp.secret).unwrap();
        unblind(&us, &response).unwrap()
    };

    let sig_a = make_sig(b"alpha", &mut rng);
    let sig_b = make_sig(b"beta", &mut rng);
    assert_ne!(sig_a, sig_b);
    // Both should still verify under their respective messages
    assert!(schnorr_verify(&kp.public, b"alpha", &sig_a).unwrap());
    assert!(schnorr_verify(&kp.public, b"beta", &sig_b).unwrap());
    // Cross-verification should fail
    assert!(!schnorr_verify(&kp.public, b"beta", &sig_a).unwrap());
    assert!(!schnorr_verify(&kp.public, b"alpha", &sig_b).unwrap());
}
