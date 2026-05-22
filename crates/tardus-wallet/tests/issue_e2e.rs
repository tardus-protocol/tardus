//! Crown jewel for Faz 3.1: spawn 3 validator daemons, drive a DKG
//! across them via HTTP, then use `tardus-wallet`'s `issue_coin`
//! orchestrator (the same library a real wallet would use) to mint
//! one coin. Verify the coin under the joint public key.

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
use tardus_wallet::{issue_coin, ValidatorEndpoint, WalletClientPool};
use tempfile::TempDir;

const DKG_CEREMONY: CeremonyId = CeremonyId::from_bytes([0x39; 16]);
const ISSUE_SESSION: SessionId = SessionId::from_bytes([0x33; 16]);

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

/// Locate the validator binary from the workspace `target/release/`
/// directory. The test relies on
/// `cargo build --release -p tardus-validator` having been run
/// (cargo's standard test workflow does this for `dev-dependencies`
/// of the same workspace, but not for the binary itself — so we
/// resolve via `CARGO_MANIFEST_DIR`).
fn validator_binary_path() -> std::path::PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let mut p = std::path::PathBuf::from(manifest);
    p.pop(); // remove tardus-wallet
    p.pop(); // remove crates
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
        .arg("--operator").arg(format!("w-{my_index}"))
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

/// Drive a full DKG ceremony across the 3 daemons using a synchronous
/// reqwest client. Returns the consensus joint_pk hex.
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
async fn wallet_orchestrator_issues_coin_via_three_daemons() {
    // === Phase 1: spawn 3 daemons + run DKG (sync, for setup) ===
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

    // === Phase 2: build the wallet pool ===
    let pool = WalletClientPool::new(vec![
        ValidatorEndpoint::plain(1, d1.base.clone()).unwrap(),
        ValidatorEndpoint::plain(2, d2.base.clone()).unwrap(),
        ValidatorEndpoint::plain(3, d3.base.clone()).unwrap(),
    ]).unwrap();

    // === Phase 3: wallet drives full issue (the crown jewel) ===
    let coin = issue_coin(&pool, &joint_pk, ISSUE_SESSION)
        .await
        .expect("issue_coin via wallet orchestrator");

    // === Phase 4: verify ===
    assert!(
        coin.verify(&joint_pk).unwrap(),
        "the coin minted by the wallet orchestrator MUST verify under joint_pk"
    );

    drop((d1, d2, d3));
}
