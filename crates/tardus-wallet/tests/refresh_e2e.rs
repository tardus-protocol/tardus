//! Crown jewel for Faz 3.2: spawn 3 validator daemons, drive DKG
//! over HTTP, use `tardus_wallet::issue_coin` to mint an initial
//! coin, then use `tardus_wallet::refresh_coin` to refresh it. Both
//! coins must verify under the unchanged `joint_pk`; their pubkeys
//! must differ (unlinkability).

#![allow(
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::doc_markdown
)]

use rand::rngs::OsRng;
use rand::RngCore;
use serde::Serialize;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tardus_core::PublicKey;
use tardus_mint::transcript::{CeremonyId, SessionId};
use tardus_wallet::{issue_coin, refresh_coin, ValidatorEndpoint, WalletClientPool};
use tempfile::TempDir;

const DKG_CEREMONY: CeremonyId = CeremonyId::from_bytes([0x3B; 16]);
const ISSUE_SESSION: SessionId = SessionId::from_bytes([0x3C; 16]);
const REFRESH_SESSION: SessionId = SessionId::from_bytes([0x3D; 16]);

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

fn validator_binary_path() -> std::path::PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let mut p = std::path::PathBuf::from(manifest);
    p.pop();
    p.pop();
    p.push("target");
    p.push("release");
    p.push("tardus-validator");
    assert!(
        p.exists(),
        "validator binary not found at {}. Run: cargo build --release -p tardus-validator",
        p.display()
    );
    p
}

fn spawn_daemon(my_index: u16) -> Daemon {
    let tmp = TempDir::new().unwrap();
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let seed_hex = hex::encode(seed);
    let binary = validator_binary_path();
    let child = Command::new(binary)
        .arg("--bind").arg(&bind)
        .arg("--data-dir").arg(tmp.path())
        .arg("--operator").arg(format!("wr-{my_index}"))
        .arg("--master-seed-hex").arg(&seed_hex)
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().expect("spawn");
    Daemon { child, base, seed_hex, tmp, my_index }
}

fn wait_health_blocking(base: &str, deadline: Duration) {
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

fn dkg_3_of_3(daemons: &[&Daemon]) -> String {
    let client = reqwest::blocking::Client::new();
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wallet_issues_then_refreshes_via_three_daemons() {
    // === Setup: 3 daemons + DKG ===
    let d1 = spawn_daemon(1);
    let d2 = spawn_daemon(2);
    let d3 = spawn_daemon(3);
    wait_health_blocking(&d1.base, Duration::from_secs(5));
    wait_health_blocking(&d2.base, Duration::from_secs(5));
    wait_health_blocking(&d3.base, Duration::from_secs(5));
    let daemons = [&d1, &d2, &d3];
    let joint_pk_hex = dkg_3_of_3(&daemons);
    let joint_pk_bytes: [u8; 32] = {
        let b = hex::decode(&joint_pk_hex).unwrap();
        let mut a = [0u8; 32]; a.copy_from_slice(&b); a
    };
    let joint_pk = PublicKey::from_bytes(&joint_pk_bytes).unwrap();

    // === Wallet client pool ===
    let pool = WalletClientPool::new(vec![
        ValidatorEndpoint::plain(1, d1.base.clone()).unwrap(),
        ValidatorEndpoint::plain(2, d2.base.clone()).unwrap(),
        ValidatorEndpoint::plain(3, d3.base.clone()).unwrap(),
    ]).unwrap();

    // === Step 1: issue a coin (parallel via try_join_all) ===
    let initial_coin = issue_coin(&pool, &joint_pk, ISSUE_SESSION)
        .await
        .expect("issue_coin");
    assert!(
        initial_coin.verify(&joint_pk).unwrap(),
        "initial coin must verify under joint_pk"
    );

    // === Step 2: refresh the coin (parallel + 6 rounds) ===
    let new_coin = refresh_coin(&pool, &initial_coin, &joint_pk, REFRESH_SESSION)
        .await
        .expect("refresh_coin");
    assert!(
        new_coin.verify(&joint_pk).unwrap(),
        "refreshed coin must verify under joint_pk"
    );

    // === Unlinkability: pubkeys differ ===
    assert_ne!(
        initial_coin.pubkey_bytes(),
        new_coin.pubkey_bytes(),
        "refresh must produce a coin with a fresh public key"
    );

    drop((d1, d2, d3));
}
