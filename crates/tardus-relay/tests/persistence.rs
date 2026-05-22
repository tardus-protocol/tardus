//! v5.4 persistence test: deposit messages → kill the relay → restart
//! with the same SQLite file → messages still present.

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

fn spawn(bind: &str, storage_path: &std::path::Path) -> Guard {
    let binary = env!("CARGO_BIN_EXE_tardus-relayd");
    let child = Command::new(binary)
        .arg("--bind").arg(bind)
        .arg("--operator").arg("relay-persistence")
        .arg("--storage-path").arg(storage_path)
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

const RECIPIENT: &str =
    "01010101010101010101010101010101010101010101010101010101deadbeef";

#[test]
fn sqlite_inbox_survives_restart() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db = tmp.path().join("inbox.db");
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");

    // === First boot: deposit two messages ===
    {
        let _g = spawn(&bind, &db);
        wait_for(&format!("{base}/health"), Duration::from_secs(5));
        let c = reqwest::blocking::Client::new();
        for payload in ["aabb", "ccdd"] {
            c.post(format!("{base}/inbox/{RECIPIENT}"))
                .json(&serde_json::json!({"payload_hex": payload, "ttl_secs": 3600}))
                .send()
                .unwrap();
        }
        let listed: serde_json::Value = c
            .get(format!("{base}/inbox/{RECIPIENT}"))
            .send()
            .unwrap()
            .json()
            .unwrap();
        assert_eq!(listed["messages"].as_array().unwrap().len(), 2);
        // _g drops here → daemon process killed.
    }

    // Give the OS a beat to release the port.
    std::thread::sleep(Duration::from_millis(200));

    // === Second boot: same DB → messages persist ===
    {
        // Use a fresh port for the second boot (in case the first port
        // is still in TIME_WAIT).
        let port2 = pick_free_port();
        let bind2 = format!("127.0.0.1:{port2}");
        let base2 = format!("http://{bind2}");
        let _g = spawn(&bind2, &db);
        wait_for(&format!("{base2}/health"), Duration::from_secs(5));

        let c = reqwest::blocking::Client::new();
        let listed: serde_json::Value = c
            .get(format!("{base2}/inbox/{RECIPIENT}"))
            .send()
            .unwrap()
            .json()
            .unwrap();
        let msgs = listed["messages"].as_array().unwrap();
        assert_eq!(
            msgs.len(),
            2,
            "messages must survive the daemon restart with SQLite backend"
        );
        let payloads: Vec<&str> = msgs
            .iter()
            .map(|m| m.get("payload_hex").and_then(|v| v.as_str()).unwrap_or(""))
            .collect();
        assert!(payloads.contains(&"aabb"));
        assert!(payloads.contains(&"ccdd"));
    }
}

#[test]
fn sqlite_inbox_remove_persists() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db = tmp.path().join("inbox.db");
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");

    let deposited_id;
    {
        let _g = spawn(&bind, &db);
        wait_for(&format!("{base}/health"), Duration::from_secs(5));
        let c = reqwest::blocking::Client::new();
        let resp: serde_json::Value = c
            .post(format!("{base}/inbox/{RECIPIENT}"))
            .json(&serde_json::json!({"payload_hex": "1234", "ttl_secs": 3600}))
            .send()
            .unwrap()
            .json()
            .unwrap();
        deposited_id = resp["id"].as_str().unwrap().to_string();

        // Delete it
        let del: serde_json::Value = c
            .delete(format!("{base}/inbox/{RECIPIENT}/{deposited_id}"))
            .send()
            .unwrap()
            .json()
            .unwrap();
        assert_eq!(del["removed"], true);
    }

    std::thread::sleep(Duration::from_millis(200));
    {
        let port2 = pick_free_port();
        let bind2 = format!("127.0.0.1:{port2}");
        let base2 = format!("http://{bind2}");
        let _g = spawn(&bind2, &db);
        wait_for(&format!("{base2}/health"), Duration::from_secs(5));
        let c = reqwest::blocking::Client::new();
        let listed: serde_json::Value = c
            .get(format!("{base2}/inbox/{RECIPIENT}"))
            .send()
            .unwrap()
            .json()
            .unwrap();
        assert_eq!(
            listed["messages"].as_array().unwrap().len(),
            0,
            "DELETE must persist across restart"
        );
    }
}
