//! Tests for the v2.4 observability + admin endpoints.

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

fn spawn(bind: &str, data_dir: &std::path::Path, admin_token: Option<&str>) -> Guard {
    let binary = env!("CARGO_BIN_EXE_tardus-validator");
    let mut cmd = Command::new(binary);
    cmd.arg("--bind").arg(bind)
        .arg("--data-dir").arg(data_dir)
        .arg("--operator").arg("obs-test");
    if let Some(token) = admin_token {
        cmd.arg("--admin-token").arg(token);
    }
    let child = cmd
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
fn metrics_endpoint_returns_prometheus_format() {
    let tmp = tempfile::TempDir::new().unwrap();
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let _guard = spawn(&bind, tmp.path(), None);
    wait_for(&format!("{base}/health"), Duration::from_secs(5));

    let c = reqwest::blocking::Client::new();
    // hit /health a few times so the counter is non-zero
    for _ in 0..3 {
        c.get(format!("{base}/health")).send().unwrap();
    }

    let resp = c.get(format!("{base}/metrics")).send().unwrap();
    assert!(resp.status().is_success());
    let ct = resp.headers().get("content-type").unwrap().to_str().unwrap();
    assert!(ct.starts_with("text/plain"), "got content-type {ct}");

    let body = resp.text().unwrap();
    // Prometheus format basics
    assert!(body.contains("# HELP validator_uptime_seconds"));
    assert!(body.contains("# TYPE validator_uptime_seconds gauge"));
    assert!(body.contains("validator_share_loaded 0"));
    // health probes counter advanced (3 + at least 1 from wait_for)
    let line = body
        .lines()
        .find(|l| l.starts_with("validator_health_probes_total "))
        .expect("counter line present");
    let n: u64 = line
        .split_ascii_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    assert!(n >= 4, "expected ≥4 probes, got {n}");
    // sign + refresh counters present at zero
    assert!(body.contains("validator_sign_sessions_total 0"));
    assert!(body.contains("validator_refresh_sessions_total 0"));
    assert!(body.contains("validator_sign_sessions_inflight 0"));
}

#[test]
fn admin_endpoints_require_token() {
    let tmp = tempfile::TempDir::new().unwrap();
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let _guard = spawn(&bind, tmp.path(), Some("secret-token-42"));
    wait_for(&format!("{base}/health"), Duration::from_secs(5));

    let c = reqwest::blocking::Client::new();

    // No token → 401
    let r = c.get(format!("{base}/admin/sessions")).send().unwrap();
    assert_eq!(r.status().as_u16(), 401);

    // Wrong token → 401
    let r = c
        .get(format!("{base}/admin/sessions"))
        .header("X-Admin-Token", "wrong")
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);

    // Correct token → 200
    let r: serde_json::Value = c
        .get(format!("{base}/admin/sessions"))
        .header("X-Admin-Token", "secret-token-42")
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(r["sign_inflight"], 0);
    assert_eq!(r["refresh_inflight"], 0);
}

#[test]
fn admin_endpoints_disabled_when_no_token_configured() {
    let tmp = tempfile::TempDir::new().unwrap();
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    // No --admin-token argument
    let _guard = spawn(&bind, tmp.path(), None);
    wait_for(&format!("{base}/health"), Duration::from_secs(5));

    let c = reqwest::blocking::Client::new();
    // Even with a header, admin endpoints are 403 when token is unset.
    let r = c
        .get(format!("{base}/admin/sessions"))
        .header("X-Admin-Token", "any-string")
        .send()
        .unwrap();
    assert_eq!(r.status().as_u16(), 403);
}
