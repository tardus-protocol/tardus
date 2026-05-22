//! Crown jewel for Faz 2.3: spawn the validator daemon as one
//! participant in a real 3-of-3 κ-fold cut-and-choose refresh.
//! Verifies that the daemon's `/refresh/round1` and `/refresh/round5`
//! endpoints compose with `tardus_refresh`'s in-process API to produce
//! a freshly-issued coin under the unchanged joint public key.

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
use tardus_core::{
    blind_request, unblind, BlindCommit, PublicKey, SecretKey, UserState,
};
use tardus_mint::{
    dkg::{dkg_finalize, dkg_start, DkgFinalised, PeerContribution},
    sign::{
        aggregate_commitments, aggregate_responses, partial_sign, validator_round1,
    },
    transcript::{CeremonyId, SessionId},
    vss::{h_generator, VssParameters},
};
use tardus_refresh::{
    coin::Coin,
    refresh::{
        aggregate_refresh_round1, aggregate_refresh_round5, mint_refresh_round3,
        mint_refresh_verify_reveal, user_refresh_round2, user_refresh_round4, user_refresh_round6,
        validator_refresh_round1, validator_refresh_round5, MintRefreshR1Output,
        ValidatorRefreshR1Output, ValidatorRefreshR5Output, DEFAULT_KAPPA,
    },
};
use tardus_validator::storage::{share_path, write_share_record, ValidatorShareRecord};
use tempfile::TempDir;

const DKG_CEREMONY: CeremonyId = CeremonyId::from_bytes([0x99; 16]);
const ISSUE_SESSION: SessionId = SessionId::from_bytes([0xCA; 16]);
const REFRESH_SESSION: SessionId = SessionId::from_bytes([0xCB; 16]);

fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
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
        .arg("--bind").arg(bind)
        .arg("--data-dir").arg(data_dir)
        .arg("--operator").arg("tv-refresh-e2e")
        .arg("--master-seed-hex").arg(seed_hex)
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().expect("spawn daemon");
    DaemonGuard { child }
}

fn wait_for_health(url: &str, deadline: Duration) {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(1))
        .build().unwrap();
    let start = Instant::now();
    while start.elapsed() < deadline {
        if client.get(url).send().is_ok_and(|r| r.status().is_success()) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("daemon at {url} not healthy");
}

fn run_dkg(n: u16, t: u16) -> Vec<DkgFinalised> {
    let mut rng = OsRng;
    let h = h_generator();
    let params = VssParameters::new(n, t).unwrap();
    let outputs: Vec<_> = (1..=n)
        .map(|i| dkg_start(DKG_CEREMONY, i, params, &h, &mut rng).unwrap())
        .collect();
    (1..=n).map(|i| {
        let i_idx = (i - 1) as usize;
        let received: Vec<PeerContribution> = (1..=n).filter(|&k| k != i).map(|k| {
            let k_idx = (k - 1) as usize;
            PeerContribution {
                broadcast: outputs[k_idx].broadcast.clone(),
                share_for_me: outputs[k_idx].shares[(i - 1) as usize].clone(),
            }
        }).collect();
        dkg_finalize(&outputs[i_idx], &received, &h).unwrap()
    }).collect()
}

/// Run a full in-process threshold sign issue to produce a valid coin.
fn issue_coin_inproc(finalised: &[DkgFinalised], signing_set: &[u16]) -> Coin {
    let mut rng = OsRng;
    let joint_pk = finalised[0].joint_pk;
    let r1: Vec<_> = signing_set.iter().map(|&i| {
        validator_round1(ISSUE_SESSION, i, &mut rng)
    }).collect();
    let r1_outputs: Vec<_> = r1.iter().map(|(o, _)| *o).collect();
    let blind_commit: BlindCommit =
        aggregate_commitments(ISSUE_SESSION, signing_set, &r1_outputs).unwrap();
    let coin_secret = SecretKey::random(&mut rng);
    let coin_pk = PublicKey::from_secret(&coin_secret);
    let coin_pk_bytes = coin_pk.to_bytes();
    let (challenge, user_state): (_, UserState) =
        blind_request(&blind_commit, &joint_pk, &coin_pk_bytes, &mut rng).unwrap();
    let r3_outputs: Vec<_> = r1.iter().map(|(_, state)| {
        let f = finalised.iter().find(|f| f.my_index == state.my_index).unwrap();
        partial_sign(state, &challenge, &f.my_share, signing_set).unwrap()
    }).collect();
    let blind_response = aggregate_responses(ISSUE_SESSION, signing_set, &r3_outputs).unwrap();
    let signature = unblind(&user_state, &blind_response).unwrap();
    Coin::new(coin_secret, coin_pk_bytes, signature).unwrap()
}

#[derive(Serialize)]
struct R1Req {
    session_id_hex: String,
    kappa: u8,
}
#[derive(Serialize)]
struct R5Req {
    session_id_hex: String,
    signing_set: Vec<u16>,
    gamma_star: u8,
    user_challenges_hex: Vec<String>,
    melted_coin_pubkey_hex: String,
    melted_coin_signature_hex: String,
}

#[test]
fn daemon_participates_in_refresh_ceremony_3_of_3() {
    // === 1. DKG 3-of-3 ===
    let n: u16 = 3;
    let t: u16 = 3;
    let finalised = run_dkg(n, t);
    let joint_pk = finalised[0].joint_pk;
    let signing_set: Vec<u16> = finalised.iter().map(|f| f.my_index).collect();

    // === 2. Issue an initial coin in-process (no daemon involvement) ===
    let initial_coin = issue_coin_inproc(&finalised, &signing_set);
    assert!(
        initial_coin.verify(&joint_pk).unwrap(),
        "initial coin must verify under joint_pk"
    );

    // === 3. Seal validator 1's share to disk ===
    let v1 = &finalised[0];
    let mut keyset_id = [0u8; 33];
    keyset_id[0] = 0x02;
    keyset_id[1..].copy_from_slice(&joint_pk.to_bytes());
    let record = ValidatorShareRecord {
        keyset_id,
        my_index: v1.my_index,
        n, t, epoch: 1,
        joint_pk_bytes: joint_pk.to_bytes(),
        my_share_bytes: v1.my_share.to_bytes(),
        qual: v1.qual.clone(),
    };
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let tmp = TempDir::new().unwrap();
    let path = share_path(tmp.path(), &keyset_id);
    write_share_record(&path, &seed, &record).unwrap();

    // === 4. Spawn daemon ===
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let _guard = spawn_daemon(&bind, tmp.path(), &hex::encode(seed));
    wait_for_health(&format!("{base}/health"), Duration::from_secs(5));

    let client = reqwest::blocking::Client::new();
    let kappa = DEFAULT_KAPPA;
    let session_id_hex = hex::encode(REFRESH_SESSION.to_bytes());

    // === 5. Refresh Round 1: daemon contributes ===
    let daemon_r1: serde_json::Value = client
        .post(format!("{base}/refresh/round1"))
        .json(&R1Req {
            session_id_hex: session_id_hex.clone(),
            kappa,
        })
        .send().unwrap().json().unwrap();
    assert_eq!(daemon_r1["from_index"].as_u64().unwrap(), u64::from(v1.my_index));
    let daemon_r_per_candidate: Vec<[u8; 32]> = daemon_r1["r_per_candidate_hex"]
        .as_array().unwrap()
        .iter().map(|x| {
            let b = hex::decode(x.as_str().unwrap()).unwrap();
            let mut a = [0u8; 32]; a.copy_from_slice(&b); a
        }).collect();
    assert_eq!(daemon_r_per_candidate.len(), kappa as usize);
    let daemon_r1_typed = ValidatorRefreshR1Output {
        session_id: REFRESH_SESSION,
        from_index: v1.my_index,
        r_per_candidate: daemon_r_per_candidate,
    };

    // Validators 2 and 3 in-process.
    let mut rng = OsRng;
    let (r1_v2_out, r1_v2_state) =
        validator_refresh_round1(REFRESH_SESSION, finalised[1].my_index, kappa, &mut rng).unwrap();
    let (r1_v3_out, r1_v3_state) =
        validator_refresh_round1(REFRESH_SESSION, finalised[2].my_index, kappa, &mut rng).unwrap();

    // === 6. Aggregate R1 → MintRefreshR1Output ===
    let mint_r1: MintRefreshR1Output = aggregate_refresh_round1(
        REFRESH_SESSION, kappa, &signing_set,
        &[daemon_r1_typed.clone(), r1_v2_out, r1_v3_out],
    ).unwrap();

    // === 7. User round 2: produce challenges + reveal data ===
    let (user_r2, user_state) =
        user_refresh_round2(REFRESH_SESSION, &mint_r1, &joint_pk, &initial_coin, &mut rng).unwrap();

    // === 8. Mint round 3: derive gamma_star ===
    let challenge = mint_refresh_round3(REFRESH_SESSION, &user_r2, &joint_pk).unwrap();

    // === 9. User round 4: reveal κ-1 candidates ===
    let reveal = user_refresh_round4(&user_state, &challenge).unwrap();

    // === 10. Mint verify reveal ===
    mint_refresh_verify_reveal(&user_r2, &mint_r1, &challenge, &reveal, &joint_pk).unwrap();

    // === 11. Refresh Round 5: daemon contributes ===
    let daemon_r5: serde_json::Value = client
        .post(format!("{base}/refresh/round5"))
        .json(&R5Req {
            session_id_hex: session_id_hex.clone(),
            signing_set: signing_set.clone(),
            gamma_star: challenge.gamma_star,
            user_challenges_hex: user_r2.challenges.iter().map(hex::encode).collect(),
            melted_coin_pubkey_hex: hex::encode(user_r2.melted_coin_pubkey),
            melted_coin_signature_hex: hex::encode(user_r2.melted_coin_signature.to_bytes()),
        })
        .send().unwrap().json().unwrap();
    assert_eq!(
        daemon_r5["from_index"].as_u64().unwrap(),
        u64::from(v1.my_index),
        "daemon partial should come from validator 1"
    );
    let s_1_bytes = {
        let s = daemon_r5["s_partial_hex"].as_str().unwrap();
        let b = hex::decode(s).unwrap();
        let mut a = [0u8; 32]; a.copy_from_slice(&b); a
    };
    let daemon_s_partial = ValidatorRefreshR5Output {
        session_id: REFRESH_SESSION,
        from_index: v1.my_index,
        s_partial: s_1_bytes,
    };

    // Validators 2 and 3 partial_sign in-process.
    let s_v2 = validator_refresh_round5(
        &r1_v2_state, &user_r2, &challenge, &finalised[1].my_share, &signing_set,
    ).unwrap();
    let s_v3 = validator_refresh_round5(
        &r1_v3_state, &user_r2, &challenge, &finalised[2].my_share, &signing_set,
    ).unwrap();

    // === 12. Aggregate R5 + user round 6 → new Coin ===
    let mint_r5 =
        aggregate_refresh_round5(REFRESH_SESSION, &signing_set, &[daemon_s_partial, s_v2, s_v3])
            .unwrap();
    let new_coin = user_refresh_round6(&user_state, &challenge, &mint_r5, &joint_pk).unwrap();

    // === 13. The new coin verifies under the unchanged joint_pk ===
    assert!(
        new_coin.verify(&joint_pk).unwrap(),
        "refreshed coin MUST verify under the same joint_pk used at issuance"
    );
    // Sanity: new coin is unlinkable to old (different pubkey).
    assert_ne!(initial_coin.pubkey_bytes(), new_coin.pubkey_bytes());

    // === 14. Replay protection: second /refresh/round5 with same session → 404 ===
    let dup: serde_json::Value = client
        .post(format!("{base}/refresh/round5"))
        .json(&R5Req {
            session_id_hex,
            signing_set,
            gamma_star: challenge.gamma_star,
            user_challenges_hex: user_r2.challenges.iter().map(hex::encode).collect(),
            melted_coin_pubkey_hex: hex::encode(user_r2.melted_coin_pubkey),
            melted_coin_signature_hex: hex::encode(user_r2.melted_coin_signature.to_bytes()),
        })
        .send().unwrap().json().unwrap();
    assert!(dup.get("error").is_some(), "second Round-5 call MUST fail");
}
