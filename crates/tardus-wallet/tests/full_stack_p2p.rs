//! **Ultimate crown jewel** — spawn 3 validator daemons + 1 relay,
//! drive a complete TARDUS P2P payment cycle through the actual
//! binaries, and verify every cryptographic invariant.
//!
//! ```text
//!   spawn 3 validator daemons  (separate processes)
//!   spawn 1 relay daemon       (separate process)
//!     │
//!     ↓
//!   DKG ceremony over HTTP  → joint_pk consensus (3-of-3)
//!     │
//!     ↓
//!   Alice = wallet::issue_coin(pool, joint_pk)  → Coin A (verifies)
//!     │
//!     ↓
//!   Alice ▶ sealed_box::seal(JSON(Coin A), bob_recv_pk)
//!     │
//!     ↓
//!   POST /inbox/{bob_recv_pk}    (payload OPAQUE to relay)
//!     │
//!     ↓
//!   Bob ▶ GET /inbox/{bob_recv_pk}
//!     │
//!     ↓
//!   Bob ▶ sealed_box::open(payload, bob_recv_sk) → JSON → Coin A
//!     │
//!     ↓
//!   Bob ▶ wallet::refresh_coin(pool, Coin A) → Coin B (verifies)
//!     │
//!     ↓
//!   ASSERT: Coin A verifies under joint_pk
//!   ASSERT: Coin B verifies under joint_pk
//!   ASSERT: Coin A.pubkey ≠ Coin B.pubkey   (unlinkability)
//! ```

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
use tardus_core::{PublicKey, Signature};
use tardus_mint::transcript::{CeremonyId, SessionId};
use tardus_refresh::coin::Coin;
use tardus_wallet::{
    derive_master_seed, derive_receiving_keypair, issue_coin, parse_mnemonic, refresh_coin,
    sealed_box, ValidatorEndpoint, WalletClientPool,
};
use tempfile::TempDir;

const DKG_CEREMONY: CeremonyId = CeremonyId::from_bytes([0x60; 16]);
const ISSUE_SESSION: SessionId = SessionId::from_bytes([0x61; 16]);
const REFRESH_SESSION: SessionId = SessionId::from_bytes([0x62; 16]);

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

struct Relay {
    child: Child,
    base: String,
    #[allow(dead_code)]
    tmp: TempDir,
}
impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn workspace_binary(name: &str) -> std::path::PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let mut p = std::path::PathBuf::from(manifest);
    p.pop();
    p.pop();
    p.push("target");
    p.push("release");
    p.push(name);
    assert!(
        p.exists(),
        "binary not found at {}. Run: cargo build --release first",
        p.display()
    );
    p
}

fn spawn_validator(my_index: u16) -> Daemon {
    let tmp = TempDir::new().unwrap();
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let seed_hex = hex::encode(seed);
    let binary = workspace_binary("tardus-validator");
    let child = Command::new(binary)
        .arg("--bind").arg(&bind)
        .arg("--data-dir").arg(tmp.path())
        .arg("--operator").arg(format!("full-{my_index}"))
        .arg("--master-seed-hex").arg(&seed_hex)
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().expect("spawn validator");
    Daemon { child, base, seed_hex, tmp, my_index }
}

fn spawn_relay() -> Relay {
    let tmp = TempDir::new().unwrap();
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let binary = workspace_binary("tardus-relayd");
    let child = Command::new(binary)
        .arg("--bind").arg(&bind)
        .arg("--operator").arg("full-stack-relay")
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().expect("spawn relay");
    Relay { child, base, tmp }
}

fn wait_for(url: &str, deadline: Duration) {
    let c = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(1)).build().unwrap();
    let start = Instant::now();
    while start.elapsed() < deadline {
        if c.get(url).send().is_ok_and(|r| r.status().is_success()) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("not healthy: {url}");
}

#[derive(Serialize)]
struct DkgStartReq { ceremony_id_hex: String, my_index: u16, n: u16, t: u16 }
#[derive(Serialize)]
struct DkgContribReq {
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
    let mut bcs = std::collections::HashMap::<u16, String>::new();
    let mut shs = std::collections::HashMap::<u16, Vec<String>>::new();
    for d in daemons {
        let r: serde_json::Value = client
            .post(format!("{}/dkg/start", d.base))
            .json(&DkgStartReq { ceremony_id_hex: ceremony_hex.clone(), my_index: d.my_index, n: 3, t: 3 })
            .send().unwrap().json().unwrap();
        bcs.insert(d.my_index, r["broadcast_borsh_hex"].as_str().unwrap().to_string());
        shs.insert(d.my_index, r["shares_borsh_hex"].as_array().unwrap().iter()
            .map(|x| x.as_str().unwrap().to_string()).collect());
    }
    for d in daemons {
        for other in daemons {
            if other.my_index == d.my_index { continue; }
            client.post(format!("{}/dkg/contribute", d.base))
                .json(&DkgContribReq {
                    ceremony_id_hex: ceremony_hex.clone(),
                    from_index: other.my_index,
                    broadcast_borsh_hex: bcs[&other.my_index].clone(),
                    share_for_me_borsh_hex: shs[&other.my_index][(d.my_index - 1) as usize].clone(),
                })
                .send().unwrap();
        }
    }
    let mut joint_pks = Vec::new();
    for d in daemons {
        let r: serde_json::Value = client
            .post(format!("{}/dkg/finalize", d.base))
            .json(&DkgFinalizeReq { ceremony_id_hex: ceremony_hex.clone() })
            .send().unwrap().json().unwrap();
        joint_pks.push(r["joint_pk_hex"].as_str().unwrap().to_string());
    }
    assert_eq!(joint_pks[0], joint_pks[1]);
    assert_eq!(joint_pks[1], joint_pks[2]);
    joint_pks.into_iter().next().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn full_stack_encrypted_p2p_payment() {
    // === 1. spawn the whole TARDUS stack ===
    let v1 = spawn_validator(1);
    let v2 = spawn_validator(2);
    let v3 = spawn_validator(3);
    let relay = spawn_relay();
    wait_for(&format!("{}/health", v1.base), Duration::from_secs(5));
    wait_for(&format!("{}/health", v2.base), Duration::from_secs(5));
    wait_for(&format!("{}/health", v3.base), Duration::from_secs(5));
    wait_for(&format!("{}/health", relay.base), Duration::from_secs(5));
    let daemons = [&v1, &v2, &v3];

    // === 2. DKG ceremony — consensus on joint_pk ===
    let joint_pk_hex = dkg_3_of_3(&daemons);
    let joint_pk_bytes: [u8; 32] = {
        let b = hex::decode(&joint_pk_hex).unwrap();
        let mut a = [0u8; 32]; a.copy_from_slice(&b); a
    };
    let joint_pk = PublicKey::from_bytes(&joint_pk_bytes).unwrap();

    // === 3. Bob derives his receiving identity from BIP-39 ===
    let bob_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let bob_mnemonic = parse_mnemonic(bob_phrase).unwrap();
    let bob_seed = derive_master_seed(&bob_mnemonic, "");
    let (bob_recv_sk, bob_recv_pk) = derive_receiving_keypair(&bob_seed);

    // === 4. Alice mints a coin via the wallet orchestrator ===
    let pool = WalletClientPool::new(vec![
        ValidatorEndpoint::plain(1, v1.base.clone()).unwrap(),
        ValidatorEndpoint::plain(2, v2.base.clone()).unwrap(),
        ValidatorEndpoint::plain(3, v3.base.clone()).unwrap(),
    ]).unwrap();
    let coin_a = issue_coin(&pool, &joint_pk, ISSUE_SESSION).await.expect("issue_coin");
    assert!(coin_a.verify(&joint_pk).unwrap(), "Coin A must verify under joint_pk");

    // === 5. Alice seals the coin to Bob's pubkey ===
    let payload_json = serde_json::json!({
        "coin_secret":    hex::encode(coin_a.secret().to_bytes()),
        "coin_pubkey":    hex::encode(coin_a.pubkey_bytes()),
        "coin_signature": hex::encode(coin_a.signature().to_bytes()),
        "denom":          1_000_000u64,
        "memo":           "full-stack-e2e",
    });
    let plaintext = serde_json::to_vec(&payload_json).unwrap();
    let sealed = sealed_box::seal(&plaintext, &bob_recv_pk).expect("sealed_box::seal");
    let payload_hex = hex::encode(&sealed);

    // === 6. Alice POSTs to relay ===
    let bob_pk_hex = hex::encode(bob_recv_pk);
    let http = reqwest::Client::new();
    http.post(format!("{}/inbox/{bob_pk_hex}", relay.base))
        .json(&serde_json::json!({"payload_hex": payload_hex, "ttl_secs": 3600}))
        .send().await.expect("relay POST");

    // === 7. Bob GETs from relay ===
    let listed: serde_json::Value = http
        .get(format!("{}/inbox/{bob_pk_hex}", relay.base))
        .send().await.unwrap()
        .json().await.unwrap();
    let messages = listed["messages"].as_array().expect("messages");
    assert_eq!(messages.len(), 1, "exactly one sealed message in Bob's inbox");
    let received_hex = messages[0]["payload_hex"].as_str().unwrap();
    let received_bytes = hex::decode(received_hex).unwrap();

    // === 8. Bob decrypts with his mnemonic-derived secret ===
    let decrypted = sealed_box::open(&received_bytes, &bob_recv_sk)
        .expect("sealed_box::open with Bob's recv sk");
    let decoded: serde_json::Value = serde_json::from_slice(&decrypted).unwrap();

    // Reconstruct Coin A from the decrypted JSON.
    let cs_bytes: [u8; 32] = {
        let b = hex::decode(decoded["coin_secret"].as_str().unwrap()).unwrap();
        let mut a = [0u8; 32]; a.copy_from_slice(&b); a
    };
    let cp_bytes: [u8; 32] = {
        let b = hex::decode(decoded["coin_pubkey"].as_str().unwrap()).unwrap();
        let mut a = [0u8; 32]; a.copy_from_slice(&b); a
    };
    let sig_bytes: [u8; 64] = {
        let b = hex::decode(decoded["coin_signature"].as_str().unwrap()).unwrap();
        let mut a = [0u8; 64]; a.copy_from_slice(&b); a
    };
    let coin_a_reconstructed = Coin::new(
        tardus_core::SecretKey::from_bytes(&cs_bytes).unwrap(),
        cp_bytes,
        Signature::from_bytes(&sig_bytes),
    ).unwrap();
    assert!(
        coin_a_reconstructed.verify(&joint_pk).unwrap(),
        "Coin A reconstructed from sealed payload must verify under joint_pk"
    );
    assert_eq!(coin_a_reconstructed.pubkey_bytes(), coin_a.pubkey_bytes());

    // === 9. Bob refreshes the coin via the same wallet pool ===
    let coin_b = refresh_coin(&pool, &coin_a_reconstructed, &joint_pk, REFRESH_SESSION)
        .await
        .expect("refresh_coin");
    assert!(coin_b.verify(&joint_pk).unwrap(), "Coin B must verify under joint_pk");
    assert_ne!(
        coin_a.pubkey_bytes(),
        coin_b.pubkey_bytes(),
        "refresh must produce unlinkable pubkey"
    );

    // === 10. Everything verifies; stack tears down cleanly ===
    drop((v1, v2, v3, relay));
}
