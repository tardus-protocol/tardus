//! Tests for the v2.7 transparency log (append-only hash chain).

#![allow(
    clippy::similar_names,
    clippy::doc_markdown,
    clippy::items_after_statements
)]

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

fn spawn_with_log(
    bind: &str,
    data_dir: &std::path::Path,
    log_path: &std::path::Path,
) -> Guard {
    let binary = env!("CARGO_BIN_EXE_tardus-validator");
    let child = Command::new(binary)
        .arg("--bind").arg(bind)
        .arg("--data-dir").arg(data_dir)
        .arg("--operator").arg("tlog-test")
        .arg("--transparency-log").arg(log_path)
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
    panic!("not healthy");
}

#[test]
fn boot_writes_log_entry_and_chain_verifies() {
    let tmp = tempfile::TempDir::new().unwrap();
    let log_path = tmp.path().join("tlog.jsonl");
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let _guard = spawn_with_log(&bind, tmp.path(), &log_path);
    wait_for(&format!("{base}/health"), Duration::from_secs(5));

    // Give the daemon a moment to write the boot entry.
    std::thread::sleep(Duration::from_millis(200));

    // /transparency/log → at least the Boot entry
    let c = reqwest::blocking::Client::new();
    let resp: serde_json::Value = c
        .get(format!("{base}/transparency/log"))
        .send().unwrap().json().unwrap();
    let entries = resp["entries"].as_array().unwrap();
    assert!(!entries.is_empty(), "boot must produce at least one log entry");
    let first = &entries[0];
    assert_eq!(first["event"]["type"], "boot");
    assert_eq!(first["event"]["operator"], "tlog-test");
    // genesis prev = all zero
    assert_eq!(
        first["prev_event_id"].as_str().unwrap(),
        "0000000000000000000000000000000000000000000000000000000000000000"
    );
    // /transparency/verify-chain → valid
    let verify: serde_json::Value = c
        .get(format!("{base}/transparency/verify-chain"))
        .send().unwrap().json().unwrap();
    assert_eq!(verify["valid"], true);
    assert!(verify["entries_checked"].as_u64().unwrap() >= 1);
}

#[test]
fn tampered_log_fails_verification() {
    let tmp = tempfile::TempDir::new().unwrap();
    let log_path = tmp.path().join("tlog.jsonl");
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let _guard = spawn_with_log(&bind, tmp.path(), &log_path);
    wait_for(&format!("{base}/health"), Duration::from_secs(5));
    std::thread::sleep(Duration::from_millis(200));

    // Tamper with the log file by appending a fake entry with a
    // wrong prev_event_id.
    let fake_line = "{\"event_id\":\"deadbeef000000000000000000000000000000000000000000000000000000\",\"prev_event_id\":\"00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff\",\"ts_unix_ms\":0,\"event\":{\"type\":\"boot\",\"operator\":\"injected\",\"bind_addr\":\"x\",\"share_loaded\":false,\"keyset_id_hex\":null,\"epoch\":null}}\n";
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .unwrap();
    f.write_all(fake_line.as_bytes()).unwrap();
    drop(f);

    // /transparency/verify-chain → invalid
    let c = reqwest::blocking::Client::new();
    let verify: serde_json::Value = c
        .get(format!("{base}/transparency/verify-chain"))
        .send().unwrap().json().unwrap();
    assert_eq!(verify["valid"], false);
    assert!(verify["failure_index"].as_u64().is_some());
}

#[test]
fn no_log_path_disables_endpoints() {
    let tmp = tempfile::TempDir::new().unwrap();
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    // No --transparency-log argument
    let binary = env!("CARGO_BIN_EXE_tardus-validator");
    let child = Command::new(binary)
        .arg("--bind").arg(&bind)
        .arg("--data-dir").arg(tmp.path())
        .arg("--operator").arg("tlog-disabled")
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().unwrap();
    let _guard = Guard { child };
    wait_for(&format!("{base}/health"), Duration::from_secs(5));

    let c = reqwest::blocking::Client::new();
    let r = c.get(format!("{base}/transparency/log")).send().unwrap();
    assert_eq!(r.status().as_u16(), 404);
    let r = c
        .get(format!("{base}/transparency/verify-chain"))
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);
}
