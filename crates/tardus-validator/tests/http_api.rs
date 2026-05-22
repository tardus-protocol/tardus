//! Integration test: spawn the validator binary, hit its HTTP
//! endpoints, assert correct shapes.

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Find a free TCP port by binding to :0 and reading the assigned port.
fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = l.local_addr().expect("local_addr").port();
    drop(l);
    port
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

fn spawn_daemon(bind: &str, data_dir: &std::path::Path) -> DaemonGuard {
    let binary = env!("CARGO_BIN_EXE_tardus-validator");
    let child = Command::new(binary)
        .arg("--bind")
        .arg(bind)
        .arg("--data-dir")
        .arg(data_dir)
        .arg("--operator")
        .arg("test-operator-1")
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
        if let Ok(resp) = client.get(url).send() {
            if resp.status().is_success() {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("daemon did not become healthy at {url}");
}

#[test]
fn daemon_serves_health_info_version() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let _guard = spawn_daemon(&bind, tmp.path());

    wait_for_health(&format!("{base}/health"), Duration::from_secs(5));

    let client = reqwest::blocking::Client::new();

    // /health
    let health: serde_json::Value = client
        .get(format!("{base}/health"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(health["status"], "ok");
    let probes = health["probes_served"].as_u64().unwrap();
    assert!(probes >= 1, "probes_served should increment");

    // Second /health probe → counter increments
    let health2: serde_json::Value = client
        .get(format!("{base}/health"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(
        health2["probes_served"].as_u64().unwrap(),
        probes + 1
    );

    // /info
    let info: serde_json::Value = client
        .get(format!("{base}/info"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(info["operator"], "test-operator-1");
    assert_eq!(info["share_loaded"], false);
    assert!(info["bind_addr"].as_str().unwrap().contains("127.0.0.1"));

    // /version
    let version: serde_json::Value = client
        .get(format!("{base}/version"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(version["api_version"], "tardus-validator-v0.1");
    assert!(version["crate_version"].as_str().unwrap().contains("0.1"));
}
