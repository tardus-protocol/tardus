//! Crown jewel for Faz 2.5: spawn THREE validator daemons,
//! orchestrate a full DKG ceremony across all three via HTTP, verify
//! every daemon reaches the same joint public key, then run a real
//! threshold sign session using the just-finalised shares — all over
//! HTTP, all daemons independent processes.

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

const CEREMONY_ID: CeremonyId = CeremonyId::from_bytes([0xCE; 16]);
const SIGN_SESSION: SessionId = SessionId::from_bytes([0x55; 16]);

fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

struct Daemon {
    child: Child,
    base: String,
    /// Kept alive for the lifetime of the daemon (data dir is wiped on drop).
    #[allow(dead_code)]
    seed_hex: String,
    /// Same as above — drop order matters; keep this last so the dir
    /// outlives the child process.
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
        .arg("--operator").arg(format!("dkg-{my_index}"))
        .arg("--master-seed-hex").arg(&seed_hex)
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().expect("spawn");
    Daemon { child, base, seed_hex, tmp, my_index }
}

fn wait_for_health(base: &str, deadline: Duration) {
    let c = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(1))
        .build().unwrap();
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
struct DkgStartReq {
    ceremony_id_hex: String,
    my_index: u16,
    n: u16,
    t: u16,
}
#[derive(Serialize)]
struct DkgContributeReq {
    ceremony_id_hex: String,
    from_index: u16,
    broadcast_borsh_hex: String,
    share_for_me_borsh_hex: String,
}
#[derive(Serialize)]
struct DkgFinalizeReq {
    ceremony_id_hex: String,
}
#[derive(Serialize)]
struct SignR1Req {
    session_id_hex: String,
}
#[derive(Serialize)]
struct SignR3Req {
    session_id_hex: String,
    signing_set: Vec<u16>,
    challenge_hex: String,
}

#[test]
fn three_daemons_dkg_then_threshold_sign_over_http() {
    let n: u16 = 3;
    let t: u16 = 3;
    let ceremony_hex = hex::encode(CEREMONY_ID.to_bytes());

    // === Spawn 3 daemons in parallel ===
    let d1 = spawn_daemon(1);
    let d2 = spawn_daemon(2);
    let d3 = spawn_daemon(3);
    wait_for_health(&d1.base, Duration::from_secs(5));
    wait_for_health(&d2.base, Duration::from_secs(5));
    wait_for_health(&d3.base, Duration::from_secs(5));

    let daemons = [&d1, &d2, &d3];
    let client = reqwest::blocking::Client::new();

    // === DKG Round 1: each daemon runs /dkg/start ===
    let mut broadcasts = std::collections::HashMap::<u16, String>::new();
    let mut shares = std::collections::HashMap::<u16, Vec<String>>::new();
    for d in &daemons {
        let resp: serde_json::Value = client
            .post(format!("{}/dkg/start", d.base))
            .json(&DkgStartReq {
                ceremony_id_hex: ceremony_hex.clone(),
                my_index: d.my_index,
                n,
                t,
            })
            .send().unwrap().json().unwrap();
        let bc = resp["broadcast_borsh_hex"].as_str().unwrap().to_string();
        let sh: Vec<String> = resp["shares_borsh_hex"]
            .as_array().unwrap().iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect();
        assert_eq!(sh.len(), n as usize);
        broadcasts.insert(d.my_index, bc);
        shares.insert(d.my_index, sh);
    }

    // === DKG Round 2: each daemon receives the other n-1 contributions ===
    for d in &daemons {
        for other in &daemons {
            if other.my_index == d.my_index { continue; }
            let bc = broadcasts.get(&other.my_index).unwrap().clone();
            // other dealt shares[other.my_index], one share per recipient.
            // The share for `d` (recipient with my_index = d.my_index)
            // is at position d.my_index - 1.
            let share_for_d = shares.get(&other.my_index).unwrap()
                [(d.my_index - 1) as usize]
                .clone();
            let resp: serde_json::Value = client
                .post(format!("{}/dkg/contribute", d.base))
                .json(&DkgContributeReq {
                    ceremony_id_hex: ceremony_hex.clone(),
                    from_index: other.my_index,
                    broadcast_borsh_hex: bc,
                    share_for_me_borsh_hex: share_for_d,
                })
                .send().unwrap().json().unwrap();
            let count = resp["contributions_received"].as_u64().unwrap();
            assert!(count >= 1, "contribution should have been recorded");
        }
    }

    // === DKG finalisation: each daemon runs /dkg/finalize ===
    let mut joint_pks = Vec::new();
    for d in &daemons {
        let resp: serde_json::Value = client
            .post(format!("{}/dkg/finalize", d.base))
            .json(&DkgFinalizeReq { ceremony_id_hex: ceremony_hex.clone() })
            .send().unwrap().json().unwrap();
        let pk_hex = resp["joint_pk_hex"].as_str().unwrap().to_string();
        let persisted = resp["share_persisted"].as_bool().unwrap();
        let my_index = u16::try_from(resp["my_index"].as_u64().unwrap()).unwrap();
        assert_eq!(my_index, d.my_index);
        assert!(persisted, "share should persist when master_seed configured");
        joint_pks.push(pk_hex);
    }
    // CONSENSUS CHECK: all daemons must agree on the same joint public key.
    assert_eq!(joint_pks[0], joint_pks[1]);
    assert_eq!(joint_pks[1], joint_pks[2]);
    let joint_pk_hex = joint_pks[0].clone();
    let joint_pk_bytes: [u8; 32] = {
        let b = hex::decode(&joint_pk_hex).unwrap();
        let mut a = [0u8; 32]; a.copy_from_slice(&b); a
    };
    let joint_pk = PublicKey::from_bytes(&joint_pk_bytes).unwrap();

    // === /info each daemon now shows share_loaded=true ===
    for d in &daemons {
        let info: serde_json::Value = client
            .get(format!("{}/info", d.base))
            .send().unwrap().json().unwrap();
        assert_eq!(info["share_loaded"], true);
        assert_eq!(
            info["my_index"].as_u64().unwrap(),
            u64::from(d.my_index)
        );
    }

    // === Threshold sign: all 3 daemons sign together over HTTP ===
    let session_id_hex = hex::encode(SIGN_SESSION.to_bytes());
    let signing_set: Vec<u16> = vec![1, 2, 3];

    // /sign/round1 from each daemon
    let mut r1_outputs = Vec::new();
    for d in &daemons {
        let resp: serde_json::Value = client
            .post(format!("{}/sign/round1", d.base))
            .json(&SignR1Req { session_id_hex: session_id_hex.clone() })
            .send().unwrap().json().unwrap();
        let r_hex = resp["r_i_hex"].as_str().unwrap();
        let r_bytes = hex::decode(r_hex).unwrap();
        let mut r = [0u8; 32]; r.copy_from_slice(&r_bytes);
        r1_outputs.push(ValidatorR1Output {
            from_index: d.my_index,
            session_id: SIGN_SESSION,
            r_i: r,
        });
    }

    // Aggregate R1
    let blind_commit: BlindCommit = aggregate_commitments(SIGN_SESSION, &signing_set, &r1_outputs).unwrap();

    // User: blind_request
    let mut rng = OsRng;
    let coin_secret = SecretKey::random(&mut rng);
    let coin_pk = PublicKey::from_secret(&coin_secret);
    let coin_pk_bytes = coin_pk.to_bytes();
    let (challenge, user_state): (_, UserState) =
        blind_request(&blind_commit, &joint_pk, &coin_pk_bytes, &mut rng).unwrap();

    // /sign/round3 from each daemon
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
        let s_hex = resp["s_i_hex"].as_str().unwrap();
        let s_bytes = hex::decode(s_hex).unwrap();
        let mut s = [0u8; 32]; s.copy_from_slice(&s_bytes);
        r3_outputs.push(ValidatorR3Output {
            from_index: d.my_index,
            session_id: SIGN_SESSION,
            s_i: s,
        });
    }

    // Aggregate R3 + unblind
    let blind_response = aggregate_responses(SIGN_SESSION, &signing_set, &r3_outputs).unwrap();
    let signature = unblind(&user_state, &blind_response).unwrap();

    // *** ULTIMATE VERIFICATION ***
    let ok = schnorr_verify(&joint_pk, &coin_pk_bytes, &signature).unwrap();
    assert!(
        ok,
        "the signature produced by 3 INDEPENDENT validator daemons via HTTP MUST verify under the joint_pk they DKG'd over HTTP"
    );
    drop((d1, d2, d3));
}
