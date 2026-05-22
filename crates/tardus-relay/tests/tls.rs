//! Tests for v5.2 relay TLS support.

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

fn write_self_signed_cert(tmp: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf, Vec<u8>) {
    let key = KeyPair::generate().unwrap();
    let params = CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_path = tmp.join("cert.pem");
    let key_path = tmp.join("key.pem");
    let pem_bytes = cert.pem().into_bytes();
    std::fs::write(&cert_path, &pem_bytes).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    (cert_path, key_path, pem_bytes)
}

fn spawn_tls(bind: &str, cert: &std::path::Path, key: &std::path::Path) -> Guard {
    let binary = env!("CARGO_BIN_EXE_tardus-relayd");
    let child = Command::new(binary)
        .arg("--bind").arg(bind)
        .arg("--operator").arg("relay-tls-test")
        .arg("--tls-cert").arg(cert)
        .arg("--tls-key").arg(key)
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().expect("spawn");
    Guard { child }
}

fn wait_https(url: &str, cert_pem: &[u8], deadline: Duration) {
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
    panic!("HTTPS relay at {url} did not become healthy");
}

#[test]
fn relay_serves_https_with_self_signed() {
    let tmp = TempDir::new().unwrap();
    let (cert_path, key_path, cert_pem) = write_self_signed_cert(tmp.path());
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("https://{bind}");
    let _guard = spawn_tls(&bind, &cert_path, &key_path);
    wait_https(&format!("{base}/health"), &cert_pem, Duration::from_secs(5));

    let cert = reqwest::Certificate::from_pem(&cert_pem).unwrap();
    let client = reqwest::blocking::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(cert)
        .build().unwrap();
    let h: serde_json::Value = client
        .get(format!("{base}/health"))
        .send().unwrap().json().unwrap();
    assert_eq!(h["status"], "ok");

    // Roundtrip inbox over HTTPS.
    let recipient = "aa".repeat(32);
    client.post(format!("{base}/inbox/{recipient}"))
        .json(&serde_json::json!({"payload_hex":"deadbeef"}))
        .send().unwrap();
    let listed: serde_json::Value = client
        .get(format!("{base}/inbox/{recipient}"))
        .send().unwrap().json().unwrap();
    assert_eq!(listed["messages"].as_array().unwrap().len(), 1);
}

#[test]
fn default_client_rejects_self_signed() {
    let tmp = TempDir::new().unwrap();
    let (cert_path, key_path, cert_pem) = write_self_signed_cert(tmp.path());
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("https://{bind}");
    let _guard = spawn_tls(&bind, &cert_path, &key_path);
    wait_https(&format!("{base}/health"), &cert_pem, Duration::from_secs(5));

    let c = reqwest::blocking::Client::builder()
        .use_rustls_tls()
        .build().unwrap();
    let r = c.get(format!("{base}/health")).send();
    assert!(r.is_err(), "default client must reject unpinned self-signed");
}
