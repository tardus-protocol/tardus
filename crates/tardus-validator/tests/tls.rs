//! Tests for the v2.8 TLS server support.

#![allow(clippy::similar_names, clippy::doc_markdown)]

use rcgen::{CertificateParams, KeyPair};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

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

fn write_self_signed_cert(tmp: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let key_pair = KeyPair::generate().expect("key pair");
    let params = CertificateParams::new(vec![
        "127.0.0.1".to_string(),
        "localhost".to_string(),
    ])
    .expect("cert params");
    let cert = params.self_signed(&key_pair).expect("self-signed");
    let cert_path = tmp.join("tls-cert.pem");
    let key_path = tmp.join("tls-key.pem");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();
    (cert_path, key_path)
}

fn spawn_tls(
    bind: &str,
    data_dir: &std::path::Path,
    cert: &std::path::Path,
    key: &std::path::Path,
) -> Guard {
    let binary = env!("CARGO_BIN_EXE_tardus-validator");
    let child = Command::new(binary)
        .arg("--bind").arg(bind)
        .arg("--data-dir").arg(data_dir)
        .arg("--operator").arg("tls-test")
        .arg("--tls-cert").arg(cert)
        .arg("--tls-key").arg(key)
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().expect("spawn");
    Guard { child }
}

fn wait_https(url: &str, deadline: Duration, cert_pem: &[u8]) {
    let cert = reqwest::Certificate::from_pem(cert_pem).expect("parse cert");
    let c = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(1))
        .use_rustls_tls()
        .add_root_certificate(cert)
        .build().unwrap();
    let start = Instant::now();
    while start.elapsed() < deadline {
        if c.get(url).send().is_ok_and(|r| r.status().is_success()) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("HTTPS at {url} did not become healthy");
}

#[test]
fn daemon_serves_https_with_self_signed_cert() {
    let tmp = TempDir::new().unwrap();
    let (cert_path, key_path) = write_self_signed_cert(tmp.path());
    let cert_pem = std::fs::read(&cert_path).unwrap();

    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("https://{bind}");
    let _guard = spawn_tls(&bind, tmp.path(), &cert_path, &key_path);

    wait_https(&format!("{base}/health"), Duration::from_secs(5), &cert_pem);

    let cert = reqwest::Certificate::from_pem(&cert_pem).unwrap();
    let client = reqwest::blocking::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(cert)
        .build()
        .unwrap();

    let health: serde_json::Value = client
        .get(format!("{base}/health"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(health["status"], "ok");

    let info: serde_json::Value = client
        .get(format!("{base}/info"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(info["operator"], "tls-test");
    assert!(info["bind_addr"].as_str().unwrap().contains("127.0.0.1"));

    let version: serde_json::Value = client
        .get(format!("{base}/version"))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(version["api_version"], "tardus-validator-v0.1");
}

#[test]
fn http_client_rejects_self_signed_cert_without_pin() {
    let tmp = TempDir::new().unwrap();
    let (cert_path, key_path) = write_self_signed_cert(tmp.path());
    let cert_pem = std::fs::read(&cert_path).unwrap();
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("https://{bind}");
    let _guard = spawn_tls(&bind, tmp.path(), &cert_path, &key_path);

    // Wait for daemon to become healthy via a trusted client first.
    wait_https(&format!("{base}/health"), Duration::from_secs(5), &cert_pem);

    // A client WITHOUT the self-signed root added should reject the
    // connection (default cert verification).
    let client = reqwest::blocking::Client::builder()
        .use_rustls_tls()
        .build()
        .unwrap();
    let result = client.get(format!("{base}/health")).send();
    assert!(
        result.is_err(),
        "client without pinned self-signed cert MUST reject the connection"
    );
}

#[test]
fn mismatched_tls_flags_rejected() {
    // Only --tls-cert without --tls-key → daemon should exit non-zero.
    let tmp = TempDir::new().unwrap();
    let (cert_path, _key_path) = write_self_signed_cert(tmp.path());
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let binary = env!("CARGO_BIN_EXE_tardus-validator");
    let output = Command::new(binary)
        .arg("--bind").arg(&bind)
        .arg("--data-dir").arg(tmp.path())
        .arg("--operator").arg("tls-bad")
        .arg("--tls-cert").arg(&cert_path)
        .output()
        .expect("spawn");
    assert!(
        !output.status.success(),
        "missing --tls-key with --tls-cert MUST cause exit failure"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("tls-cert") || stderr.contains("tls-key"),
        "stderr should mention TLS flag mismatch: {stderr}"
    );
}
