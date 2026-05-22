//! Crown jewel for Faz 2.2: spawn the validator daemon as one
//! participant in a real 3-of-3 threshold blind sign, drive the other
//! two validators in-process, aggregate, unblind, and verify the
//! resulting signature under the joint public key.
//!
//! This proves the daemon's `/sign/round1` and `/sign/round3` endpoints
//! are wire-compatible with `tardus_mint`'s in-process API and that the
//! AEAD-encrypted share storage round-trips a real DKG output.

#![allow(
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::many_single_char_names
)]

use rand::rngs::OsRng;
use rand::RngCore;
use serde::Serialize;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tardus_core::{blind_request, schnorr_verify, unblind, PublicKey, UserState};
use tardus_mint::{
    dkg::{dkg_finalize, dkg_start, DkgFinalised, PeerContribution},
    sign::{
        aggregate_commitments, aggregate_responses, partial_sign, validator_round1,
        ValidatorR1Output, ValidatorR3Output,
    },
    transcript::{CeremonyId, SessionId},
    vss::{h_generator, VssParameters},
};
use tardus_validator::storage::{share_path, write_share_record, ValidatorShareRecord};
use tempfile::TempDir;

const DKG_CEREMONY: CeremonyId = CeremonyId::from_bytes([0x77; 16]);
const SIGN_SESSION: SessionId = SessionId::from_bytes([0x88; 16]);

fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

struct DaemonGuard {
    child: Child,
}
impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_daemon(bind: &str, data_dir: &std::path::Path, seed_hex: &str) -> DaemonGuard {
    let binary = env!("CARGO_BIN_EXE_tardus-validator");
    let child = Command::new(binary)
        .arg("--bind")
        .arg(bind)
        .arg("--data-dir")
        .arg(data_dir)
        .arg("--operator")
        .arg("tv-e2e")
        .arg("--master-seed-hex")
        .arg(seed_hex)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn tardus-validator");
    DaemonGuard { child }
}

fn wait_for_health(url: &str, deadline: Duration) {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();
    let start = Instant::now();
    while start.elapsed() < deadline {
        if client.get(url).send().is_ok_and(|r| r.status().is_success()) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("daemon at {url} did not become healthy");
}

fn run_dkg(n: u16, t: u16) -> Vec<DkgFinalised> {
    let mut rng = OsRng;
    let h = h_generator();
    let params = VssParameters::new(n, t).unwrap();
    let outputs: Vec<_> = (1..=n)
        .map(|i| dkg_start(DKG_CEREMONY, i, params, &h, &mut rng).unwrap())
        .collect();
    (1..=n)
        .map(|i| {
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
            dkg_finalize(&outputs[i_idx], &received, &h).unwrap()
        })
        .collect()
}

#[derive(Serialize)]
struct SignRound1Req {
    session_id_hex: String,
}
#[derive(Serialize)]
struct SignRound3Req {
    session_id_hex: String,
    signing_set: Vec<u16>,
    challenge_hex: String,
}

#[test]
fn daemon_participates_in_3_of_3_threshold_sign() {
    // --- 1. Run a 3-of-3 DKG end-to-end, off-line --------------------
    let n: u16 = 3;
    let t: u16 = 3;
    let finalised = run_dkg(n, t);
    let joint_pk = finalised[0].joint_pk;

    // --- 2. Pick validator 1, serialise its share to the daemon's storage
    let v1 = &finalised[0];
    let mut keyset_id = [0u8; 33];
    keyset_id[0] = 0x02;
    keyset_id[1..].copy_from_slice(&joint_pk.to_bytes());
    let record = ValidatorShareRecord {
        keyset_id,
        my_index: v1.my_index,
        n,
        t,
        epoch: 1,
        joint_pk_bytes: joint_pk.to_bytes(),
        my_share_bytes: v1.my_share.to_bytes(),
        qual: v1.qual.clone(),
    };

    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let tmp = TempDir::new().unwrap();
    let path = share_path(tmp.path(), &keyset_id);
    write_share_record(&path, &seed, &record).unwrap();

    // --- 3. Spawn the daemon ----------------------------------------
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let _guard = spawn_daemon(&bind, tmp.path(), &hex::encode(seed));
    wait_for_health(&format!("{base}/health"), Duration::from_secs(5));

    let client = reqwest::blocking::Client::new();

    // /info should report the loaded share
    let info: serde_json::Value = client
        .get(format!("{base}/info"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(info["share_loaded"], true);
    assert_eq!(info["my_index"].as_u64().unwrap(), u64::from(v1.my_index));
    assert_eq!(info["n"].as_u64().unwrap(), u64::from(n));
    assert_eq!(info["t"].as_u64().unwrap(), u64::from(t));

    // --- 4. Sign Round 1 --------------------------------------------
    // Daemon produces validator 1's R_1 via /sign/round1.
    let session_id_hex = hex::encode(SIGN_SESSION.to_bytes());
    let r1_resp: serde_json::Value = client
        .post(format!("{base}/sign/round1"))
        .json(&SignRound1Req {
            session_id_hex: session_id_hex.clone(),
        })
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(r1_resp["from_index"].as_u64().unwrap(), u64::from(v1.my_index));
    let r_1_bytes = {
        let s = r1_resp["r_i_hex"].as_str().unwrap();
        let b = hex::decode(s).unwrap();
        assert_eq!(b.len(), 32);
        let mut a = [0u8; 32];
        a.copy_from_slice(&b);
        a
    };
    let daemon_r1 = ValidatorR1Output {
        from_index: v1.my_index,
        session_id: SIGN_SESSION,
        r_i: r_1_bytes,
    };

    // Validators 2 and 3 run Round 1 in-process.
    let mut rng = OsRng;
    let (r2_out, r2_state) = validator_round1(SIGN_SESSION, finalised[1].my_index, &mut rng);
    let (r3_out, r3_state) = validator_round1(SIGN_SESSION, finalised[2].my_index, &mut rng);

    // --- 5. Aggregate Round 1 → BlindCommit ------------------------
    let signing_set: Vec<u16> = vec![v1.my_index, finalised[1].my_index, finalised[2].my_index];
    let blind_commit = aggregate_commitments(
        SIGN_SESSION,
        &signing_set,
        &[daemon_r1, r2_out, r3_out],
    )
    .expect("aggregate r1");

    // --- 6. User Round 2: blind ------------------------------------
    let coin_secret = tardus_core::SecretKey::random(&mut rng);
    let coin_pk = PublicKey::from_secret(&coin_secret);
    let coin_pk_bytes = coin_pk.to_bytes();
    let (challenge, user_state): (_, UserState) =
        blind_request(&blind_commit, &joint_pk, &coin_pk_bytes, &mut rng).expect("blind_request");

    // --- 7. Sign Round 3: daemon contributes -----------------------
    let r3_daemon_resp: serde_json::Value = client
        .post(format!("{base}/sign/round3"))
        .json(&SignRound3Req {
            session_id_hex: session_id_hex.clone(),
            signing_set: signing_set.clone(),
            challenge_hex: hex::encode(challenge.c),
        })
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(
        r3_daemon_resp["from_index"].as_u64().unwrap(),
        u64::from(v1.my_index)
    );
    let s_1_bytes = {
        let s = r3_daemon_resp["s_i_hex"].as_str().unwrap();
        let b = hex::decode(s).unwrap();
        let mut a = [0u8; 32];
        a.copy_from_slice(&b);
        a
    };
    let daemon_s1 = ValidatorR3Output {
        from_index: v1.my_index,
        session_id: SIGN_SESSION,
        s_i: s_1_bytes,
    };

    // Validators 2 and 3 partial_sign in-process.
    let s2 = partial_sign(
        &r2_state,
        &challenge,
        &finalised[1].my_share,
        &signing_set,
    )
    .expect("partial_sign v2");
    let s3 = partial_sign(
        &r3_state,
        &challenge,
        &finalised[2].my_share,
        &signing_set,
    )
    .expect("partial_sign v3");

    // --- 8. Aggregate Round 3 → BlindResponse ---------------------
    let blind_response =
        aggregate_responses(SIGN_SESSION, &signing_set, &[daemon_s1, s2, s3]).expect("aggregate r3");

    // --- 9. User Round 4: unblind ---------------------------------
    let signature = unblind(&user_state, &blind_response).expect("unblind");

    // --- 10. Final verification: the daemon-participating signature
    //         verifies against the joint public key.
    let verified = schnorr_verify(&joint_pk, &coin_pk_bytes, &signature)
        .expect("schnorr_verify call");
    assert!(
        verified,
        "the threshold signature with the daemon as one participant MUST verify under joint_pk"
    );

    // --- 11. Replay protection: re-using the same session id should
    //         now fail (the Round-1 state was consumed in step 7).
    let dup: serde_json::Value = client
        .post(format!("{base}/sign/round3"))
        .json(&SignRound3Req {
            session_id_hex,
            signing_set: signing_set.clone(),
            challenge_hex: hex::encode(challenge.c),
        })
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert!(
        dup.get("error").is_some(),
        "second Round-3 call MUST fail (session consumed)"
    );
}
