//! Crown jewel for Faz 2.6: spawn THREE validator daemons, run a
//! DKG ceremony, then run a RESHARE ceremony, then run a threshold
//! SIGN — all over HTTP. Verifies T5 (reshare correctness) at the
//! distributed operational level:
//!
//!   * the joint public key is unchanged by reshare
//!   * a signature produced with the post-reshare shares verifies
//!     under the original joint public key
//!   * each daemon's epoch counter advances 1 → 2

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
use tardus_core::{blind_request, schnorr_verify, unblind, BlindCommit, PublicKey, SecretKey, UserState};
use tardus_mint::sign::{
    aggregate_commitments, aggregate_responses, ValidatorR1Output, ValidatorR3Output,
};
use tardus_mint::transcript::{CeremonyId, SessionId};
use tempfile::TempDir;

const DKG_CEREMONY: CeremonyId = CeremonyId::from_bytes([0xD6; 16]);
const RESHARE_CEREMONY: CeremonyId = CeremonyId::from_bytes([0xE6; 16]);
const SIGN_SESSION: SessionId = SessionId::from_bytes([0xA6; 16]);

fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

struct Daemon {
    child: Child,
    base: String,
    #[allow(dead_code)]
    seed_hex: String,
    #[allow(dead_code)]
    tmp: TempDir,
    my_index: u16,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_daemon(my_index: u16) -> Daemon {
    let tmp = TempDir::new().unwrap();
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let seed_hex = hex::encode(seed);
    let binary = env!("CARGO_BIN_EXE_tardus-validator");
    let child = Command::new(binary)
        .arg("--bind").arg(&bind)
        .arg("--data-dir").arg(tmp.path())
        .arg("--operator").arg(format!("rs-{my_index}"))
        .arg("--master-seed-hex").arg(&seed_hex)
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().expect("spawn");
    Daemon { child, base, seed_hex, tmp, my_index }
}

fn wait_for_health(base: &str, deadline: Duration) {
    let c = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(1)).build().unwrap();
    let start = Instant::now();
    let url = format!("{base}/health");
    while start.elapsed() < deadline {
        if c.get(&url).send().is_ok_and(|r| r.status().is_success()) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("daemon at {base} not healthy");
}

#[derive(Serialize)]
struct DkgStartReq { ceremony_id_hex: String, my_index: u16, n: u16, t: u16 }
#[derive(Serialize)]
struct DkgContributeReq {
    ceremony_id_hex: String,
    from_index: u16,
    broadcast_borsh_hex: String,
    share_for_me_borsh_hex: String,
}
#[derive(Serialize)]
struct DkgFinalizeReq { ceremony_id_hex: String }
#[derive(Serialize)]
struct ReshareStartReq { ceremony_id_hex: String }
#[derive(Serialize)]
struct ReshareContributeReq {
    ceremony_id_hex: String,
    from_index: u16,
    broadcast_borsh_hex: String,
    share_for_me_borsh_hex: String,
}
#[derive(Serialize)]
struct ReshareFinalizeReq { ceremony_id_hex: String }
#[derive(Serialize)]
struct SignR1Req { session_id_hex: String }
#[derive(Serialize)]
struct SignR3Req {
    session_id_hex: String,
    signing_set: Vec<u16>,
    challenge_hex: String,
}

fn dkg_3_of_3(daemons: &[&Daemon], client: &reqwest::blocking::Client) -> String {
    let ceremony_hex = hex::encode(DKG_CEREMONY.to_bytes());
    let mut broadcasts = std::collections::HashMap::<u16, String>::new();
    let mut shares = std::collections::HashMap::<u16, Vec<String>>::new();

    for d in daemons {
        let resp: serde_json::Value = client
            .post(format!("{}/dkg/start", d.base))
            .json(&DkgStartReq {
                ceremony_id_hex: ceremony_hex.clone(),
                my_index: d.my_index, n: 3, t: 3,
            })
            .send().unwrap().json().unwrap();
        broadcasts.insert(d.my_index, resp["broadcast_borsh_hex"].as_str().unwrap().to_string());
        let sh: Vec<String> = resp["shares_borsh_hex"].as_array().unwrap().iter()
            .map(|x| x.as_str().unwrap().to_string()).collect();
        shares.insert(d.my_index, sh);
    }
    for d in daemons {
        for other in daemons {
            if other.my_index == d.my_index { continue; }
            let bc = broadcasts[&other.my_index].clone();
            let sh = shares[&other.my_index][(d.my_index - 1) as usize].clone();
            client.post(format!("{}/dkg/contribute", d.base))
                .json(&DkgContributeReq {
                    ceremony_id_hex: ceremony_hex.clone(),
                    from_index: other.my_index,
                    broadcast_borsh_hex: bc,
                    share_for_me_borsh_hex: sh,
                })
                .send().unwrap();
        }
    }
    let mut joint_pks = Vec::new();
    for d in daemons {
        let resp: serde_json::Value = client
            .post(format!("{}/dkg/finalize", d.base))
            .json(&DkgFinalizeReq { ceremony_id_hex: ceremony_hex.clone() })
            .send().unwrap().json().unwrap();
        joint_pks.push(resp["joint_pk_hex"].as_str().unwrap().to_string());
    }
    assert_eq!(joint_pks[0], joint_pks[1]);
    assert_eq!(joint_pks[1], joint_pks[2]);
    joint_pks.into_iter().next().unwrap()
}

fn reshare_3_of_3(daemons: &[&Daemon], client: &reqwest::blocking::Client) {
    let ceremony_hex = hex::encode(RESHARE_CEREMONY.to_bytes());
    let mut broadcasts = std::collections::HashMap::<u16, String>::new();
    let mut shares = std::collections::HashMap::<u16, Vec<String>>::new();
    for d in daemons {
        let resp: serde_json::Value = client
            .post(format!("{}/reshare/start", d.base))
            .json(&ReshareStartReq { ceremony_id_hex: ceremony_hex.clone() })
            .send().unwrap().json().unwrap();
        broadcasts.insert(d.my_index, resp["broadcast_borsh_hex"].as_str().unwrap().to_string());
        let sh: Vec<String> = resp["shares_borsh_hex"].as_array().unwrap().iter()
            .map(|x| x.as_str().unwrap().to_string()).collect();
        shares.insert(d.my_index, sh);
    }
    for d in daemons {
        for other in daemons {
            if other.my_index == d.my_index { continue; }
            let bc = broadcasts[&other.my_index].clone();
            let sh = shares[&other.my_index][(d.my_index - 1) as usize].clone();
            client.post(format!("{}/reshare/contribute", d.base))
                .json(&ReshareContributeReq {
                    ceremony_id_hex: ceremony_hex.clone(),
                    from_index: other.my_index,
                    broadcast_borsh_hex: bc,
                    share_for_me_borsh_hex: sh,
                })
                .send().unwrap();
        }
    }
    for d in daemons {
        let resp: serde_json::Value = client
            .post(format!("{}/reshare/finalize", d.base))
            .json(&ReshareFinalizeReq { ceremony_id_hex: ceremony_hex.clone() })
            .send().unwrap().json().unwrap();
        // epoch advanced 1 → 2
        assert_eq!(resp["new_epoch"].as_u64().unwrap(), 2);
        assert!(resp["share_persisted"].as_bool().unwrap());
    }
}

#[test]
fn three_daemons_dkg_then_reshare_then_sign_over_http() {
    let d1 = spawn_daemon(1);
    let d2 = spawn_daemon(2);
    let d3 = spawn_daemon(3);
    wait_for_health(&d1.base, Duration::from_secs(5));
    wait_for_health(&d2.base, Duration::from_secs(5));
    wait_for_health(&d3.base, Duration::from_secs(5));
    let daemons = [&d1, &d2, &d3];
    let client = reqwest::blocking::Client::new();

    // === DKG ===
    let joint_pk_before = dkg_3_of_3(&daemons, &client);

    // === Reshare ===
    reshare_3_of_3(&daemons, &client);

    // Each daemon's /info now reports epoch=2 and SAME joint_pk
    for d in &daemons {
        let info: serde_json::Value = client
            .get(format!("{}/info", d.base))
            .send().unwrap().json().unwrap();
        assert_eq!(info["epoch"].as_u64().unwrap(), 2);
        // keyset_id_hex starts with "02" + joint_pk; extract joint_pk substring
        let keyset_id_hex = info["keyset_id_hex"].as_str().unwrap();
        assert_eq!(&keyset_id_hex[2..], &joint_pk_before);
    }

    // === Threshold sign with the POST-RESHARE shares ===
    let session_id_hex = hex::encode(SIGN_SESSION.to_bytes());
    let signing_set: Vec<u16> = vec![1, 2, 3];
    let mut r1_outputs = Vec::new();
    for d in &daemons {
        let resp: serde_json::Value = client
            .post(format!("{}/sign/round1", d.base))
            .json(&SignR1Req { session_id_hex: session_id_hex.clone() })
            .send().unwrap().json().unwrap();
        let r_bytes = hex::decode(resp["r_i_hex"].as_str().unwrap()).unwrap();
        let mut r = [0u8; 32]; r.copy_from_slice(&r_bytes);
        r1_outputs.push(ValidatorR1Output {
            from_index: d.my_index,
            session_id: SIGN_SESSION,
            r_i: r,
        });
    }
    let blind_commit: BlindCommit =
        aggregate_commitments(SIGN_SESSION, &signing_set, &r1_outputs).unwrap();

    let mut rng = OsRng;
    let coin_secret = SecretKey::random(&mut rng);
    let coin_pk = PublicKey::from_secret(&coin_secret);
    let coin_pk_bytes = coin_pk.to_bytes();
    let joint_pk_bytes: [u8; 32] = {
        let b = hex::decode(&joint_pk_before).unwrap();
        let mut a = [0u8; 32]; a.copy_from_slice(&b); a
    };
    let joint_pk = PublicKey::from_bytes(&joint_pk_bytes).unwrap();
    let (challenge, user_state): (_, UserState) =
        blind_request(&blind_commit, &joint_pk, &coin_pk_bytes, &mut rng).unwrap();

    let mut r3_outputs = Vec::new();
    for d in &daemons {
        let resp: serde_json::Value = client
            .post(format!("{}/sign/round3", d.base))
            .json(&SignR3Req {
                session_id_hex: session_id_hex.clone(),
                signing_set: signing_set.clone(),
                challenge_hex: hex::encode(challenge.c),
            })
            .send().unwrap().json().unwrap();
        let s_bytes = hex::decode(resp["s_i_hex"].as_str().unwrap()).unwrap();
        let mut s = [0u8; 32]; s.copy_from_slice(&s_bytes);
        r3_outputs.push(ValidatorR3Output {
            from_index: d.my_index,
            session_id: SIGN_SESSION,
            s_i: s,
        });
    }
    let blind_response = aggregate_responses(SIGN_SESSION, &signing_set, &r3_outputs).unwrap();
    let signature = unblind(&user_state, &blind_response).unwrap();

    // *** T5 VERIFICATION ***
    // Signature with epoch-2 shares MUST verify under the original joint_pk.
    assert!(
        schnorr_verify(&joint_pk, &coin_pk_bytes, &signature).unwrap(),
        "T5: signature produced with post-reshare shares MUST verify under the unchanged joint_pk"
    );

    drop((d1, d2, d3));
}
