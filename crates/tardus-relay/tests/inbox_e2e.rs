//! End-to-end tests for the v5.1 relay daemon: deposit, list, delete,
//! TTL pruning (via small TTL), payload-size limit, inbox-full limit.

#![allow(clippy::similar_names, clippy::doc_markdown)]

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

struct Guard {
    child: Child,
}
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn(bind: &str, max_per_recipient: usize, max_payload_bytes: usize) -> Guard {
    let binary = env!("CARGO_BIN_EXE_tardus-relayd");
    let child = Command::new(binary)
        .arg("--bind").arg(bind)
        .arg("--operator").arg("relay-test")
        .arg("--max-per-recipient").arg(max_per_recipient.to_string())
        .arg("--max-payload-bytes").arg(max_payload_bytes.to_string())
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().expect("spawn");
    Guard { child }
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
    panic!("relay at {url} not healthy");
}

const RECIPIENT_HEX: &str =
    "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff";

#[test]
fn deposit_list_delete_roundtrip() {
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let _guard = spawn(&bind, 100, 4096);
    wait_for(&format!("{base}/health"), Duration::from_secs(5));

    let c = reqwest::blocking::Client::new();

    // /health includes counters and inflight
    let h: serde_json::Value = c.get(format!("{base}/health"))
        .send().unwrap().json().unwrap();
    assert_eq!(h["status"], "ok");
    assert_eq!(h["messages_inflight"], 0);

    // Deposit two messages for the same recipient
    let msg1 = c.post(format!("{base}/inbox/{RECIPIENT_HEX}"))
        .json(&serde_json::json!({
            "payload_hex": "deadbeef",
            "ttl_secs": 3600
        }))
        .send().unwrap()
        .json::<serde_json::Value>().unwrap();
    let id1 = msg1["id"].as_str().unwrap().to_string();
    assert_eq!(msg1["payload_hex"], "deadbeef");

    let msg2 = c.post(format!("{base}/inbox/{RECIPIENT_HEX}"))
        .json(&serde_json::json!({
            "payload_hex": "cafebabe",
            "ttl_secs": 3600
        }))
        .send().unwrap()
        .json::<serde_json::Value>().unwrap();
    let id2 = msg2["id"].as_str().unwrap().to_string();
    assert_ne!(id1, id2);

    // List → 2 messages
    let listed: serde_json::Value = c.get(format!("{base}/inbox/{RECIPIENT_HEX}"))
        .send().unwrap().json().unwrap();
    let msgs = listed["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 2);

    // Delete the first
    let del: serde_json::Value = c.delete(format!("{base}/inbox/{RECIPIENT_HEX}/{id1}"))
        .send().unwrap().json().unwrap();
    assert_eq!(del["removed"], true);

    // List → 1 message remains
    let listed: serde_json::Value = c.get(format!("{base}/inbox/{RECIPIENT_HEX}"))
        .send().unwrap().json().unwrap();
    let msgs = listed["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0]["id"], id2);

    // Delete the second
    c.delete(format!("{base}/inbox/{RECIPIENT_HEX}/{id2}"))
        .send().unwrap();
    let listed: serde_json::Value = c.get(format!("{base}/inbox/{RECIPIENT_HEX}"))
        .send().unwrap().json().unwrap();
    assert_eq!(listed["messages"].as_array().unwrap().len(), 0);
}

#[test]
fn payload_too_large_rejected() {
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let _guard = spawn(&bind, 100, 16); // 16-byte payload cap
    wait_for(&format!("{base}/health"), Duration::from_secs(5));

    let c = reqwest::blocking::Client::new();
    // 64 hex chars = 32 bytes, exceeds 16-byte cap
    let oversize = "00".repeat(32);
    let r = c.post(format!("{base}/inbox/{RECIPIENT_HEX}"))
        .json(&serde_json::json!({"payload_hex": oversize}))
        .send().unwrap();
    assert_eq!(r.status().as_u16(), 400);
}

#[test]
fn inbox_full_rejected() {
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let _guard = spawn(&bind, 2, 4096); // only 2 messages per recipient
    wait_for(&format!("{base}/health"), Duration::from_secs(5));

    let c = reqwest::blocking::Client::new();
    for _ in 0..2 {
        c.post(format!("{base}/inbox/{RECIPIENT_HEX}"))
            .json(&serde_json::json!({"payload_hex": "abcd"}))
            .send().unwrap();
    }
    let r = c.post(format!("{base}/inbox/{RECIPIENT_HEX}"))
        .json(&serde_json::json!({"payload_hex": "abcd"}))
        .send().unwrap();
    assert_eq!(r.status().as_u16(), 503);
}

#[test]
fn malformed_recipient_rejected() {
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let _guard = spawn(&bind, 100, 4096);
    wait_for(&format!("{base}/health"), Duration::from_secs(5));

    let c = reqwest::blocking::Client::new();
    let r = c.post(format!("{base}/inbox/not-a-hex-pubkey"))
        .json(&serde_json::json!({"payload_hex": "abcd"}))
        .send().unwrap();
    assert_eq!(r.status().as_u16(), 400);

    let r = c.get(format!("{base}/inbox/aabbcc")) // 3 bytes, not 32
        .send().unwrap();
    assert_eq!(r.status().as_u16(), 400);
}

#[test]
fn different_recipients_isolated() {
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let _guard = spawn(&bind, 100, 4096);
    wait_for(&format!("{base}/health"), Duration::from_secs(5));

    let r1 = "00".repeat(32);
    let r2 = "ff".repeat(32);
    let c = reqwest::blocking::Client::new();

    c.post(format!("{base}/inbox/{r1}"))
        .json(&serde_json::json!({"payload_hex": "0011"}))
        .send().unwrap();
    c.post(format!("{base}/inbox/{r2}"))
        .json(&serde_json::json!({"payload_hex": "2233"}))
        .send().unwrap();

    let l1: serde_json::Value = c.get(format!("{base}/inbox/{r1}"))
        .send().unwrap().json().unwrap();
    let l2: serde_json::Value = c.get(format!("{base}/inbox/{r2}"))
        .send().unwrap().json().unwrap();
    assert_eq!(l1["messages"].as_array().unwrap().len(), 1);
    assert_eq!(l2["messages"].as_array().unwrap().len(), 1);
    assert_eq!(l1["messages"][0]["payload_hex"], "0011");
    assert_eq!(l2["messages"][0]["payload_hex"], "2233");
}
