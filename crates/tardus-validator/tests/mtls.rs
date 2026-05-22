//! Tests for the v2.9 mTLS (mutual TLS) peer authentication.

#![allow(clippy::similar_names, clippy::doc_markdown)]

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
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

/// Set of certs for an mTLS test: one CA that signs both server and
/// client certs. PEM files written under `tmp`.
struct CertBundle {
    ca_pem: Vec<u8>,
    server_cert_path: std::path::PathBuf,
    server_key_path: std::path::PathBuf,
    ca_path: std::path::PathBuf,
    client_pem_bundle: Vec<u8>,
    /// A SECOND, unrelated CA with its own client cert — used to verify
    /// that the server REJECTS client certs not signed by the trusted CA.
    other_client_pem_bundle: Vec<u8>,
}

fn make_certs(tmp: &std::path::Path) -> CertBundle {
    // === CA ===
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "tardus-mtls-ca");
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem().into_bytes();
    let ca_path = tmp.join("ca.pem");
    std::fs::write(&ca_path, &ca_pem).unwrap();

    // === Server cert (signed by CA) ===
    let server_key = KeyPair::generate().unwrap();
    let mut server_params = CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
    server_params
        .distinguished_name
        .push(DnType::CommonName, "tardus-server");
    let server_cert = server_params.signed_by(&server_key, &ca_cert, &ca_key).unwrap();
    let server_cert_path = tmp.join("server.pem");
    let server_key_path = tmp.join("server.key");
    std::fs::write(&server_cert_path, server_cert.pem()).unwrap();
    std::fs::write(&server_key_path, server_key.serialize_pem()).unwrap();

    // === Client cert (signed by CA) ===
    let client_key = KeyPair::generate().unwrap();
    let mut client_params = CertificateParams::new(vec!["client.tardus.local".to_string()]).unwrap();
    client_params
        .distinguished_name
        .push(DnType::CommonName, "tardus-client");
    let client_cert = client_params.signed_by(&client_key, &ca_cert, &ca_key).unwrap();
    let client_pem_bundle = format!("{}{}", client_cert.pem(), client_key.serialize_pem()).into_bytes();

    // === Other CA + client (NOT trusted by daemon) ===
    let other_ca_key = KeyPair::generate().unwrap();
    let mut other_ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    other_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    other_ca_params
        .distinguished_name
        .push(DnType::CommonName, "untrusted-ca");
    let other_ca_cert = other_ca_params.self_signed(&other_ca_key).unwrap();
    let other_client_key = KeyPair::generate().unwrap();
    let mut other_client_params =
        CertificateParams::new(vec!["evil.tardus.local".to_string()]).unwrap();
    other_client_params
        .distinguished_name
        .push(DnType::CommonName, "untrusted-client");
    let other_client_cert = other_client_params
        .signed_by(&other_client_key, &other_ca_cert, &other_ca_key)
        .unwrap();
    let other_client_pem_bundle = format!(
        "{}{}",
        other_client_cert.pem(),
        other_client_key.serialize_pem()
    )
    .into_bytes();

    CertBundle {
        ca_pem,
        server_cert_path,
        server_key_path,
        ca_path,
        client_pem_bundle,
        other_client_pem_bundle,
    }
}

fn spawn_mtls(bind: &str, data_dir: &std::path::Path, certs: &CertBundle) -> Guard {
    let binary = env!("CARGO_BIN_EXE_tardus-validator");
    let child = Command::new(binary)
        .arg("--bind").arg(bind)
        .arg("--data-dir").arg(data_dir)
        .arg("--operator").arg("mtls-test")
        .arg("--tls-cert").arg(&certs.server_cert_path)
        .arg("--tls-key").arg(&certs.server_key_path)
        .arg("--mtls-ca-cert").arg(&certs.ca_path)
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().expect("spawn");
    Guard { child }
}

fn build_client(certs: &CertBundle, client_bundle: Option<&[u8]>) -> reqwest::blocking::Client {
    let server_ca = reqwest::Certificate::from_pem(&certs.ca_pem).unwrap();
    let mut b = reqwest::blocking::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(server_ca)
        .timeout(Duration::from_secs(2));
    if let Some(pem) = client_bundle {
        let identity = reqwest::Identity::from_pem(pem).expect("identity");
        b = b.identity(identity);
    }
    b.build().unwrap()
}

fn wait_https_mtls(url: &str, certs: &CertBundle, deadline: Duration) {
    let c = build_client(certs, Some(&certs.client_pem_bundle));
    let start = Instant::now();
    while start.elapsed() < deadline {
        if c.get(url).send().is_ok_and(|r| r.status().is_success()) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("mTLS daemon at {url} not healthy");
}

#[test]
fn daemon_accepts_client_with_ca_signed_cert() {
    let tmp = TempDir::new().unwrap();
    let certs = make_certs(tmp.path());
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("https://{bind}");
    let _guard = spawn_mtls(&bind, tmp.path(), &certs);
    wait_https_mtls(&format!("{base}/health"), &certs, Duration::from_secs(5));

    // Client with CA-signed cert → 200
    let client = build_client(&certs, Some(&certs.client_pem_bundle));
    let health: serde_json::Value = client
        .get(format!("{base}/health"))
        .send().unwrap().json().unwrap();
    assert_eq!(health["status"], "ok");
}

#[test]
fn daemon_rejects_client_without_cert() {
    let tmp = TempDir::new().unwrap();
    let certs = make_certs(tmp.path());
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("https://{bind}");
    let _guard = spawn_mtls(&bind, tmp.path(), &certs);
    wait_https_mtls(&format!("{base}/health"), &certs, Duration::from_secs(5));

    // Client WITHOUT any cert → connection refused at TLS layer.
    let client = build_client(&certs, None);
    let result = client.get(format!("{base}/health")).send();
    assert!(
        result.is_err(),
        "mTLS server MUST reject clients that present no certificate"
    );
}

#[test]
fn daemon_rejects_client_with_untrusted_cert() {
    let tmp = TempDir::new().unwrap();
    let certs = make_certs(tmp.path());
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("https://{bind}");
    let _guard = spawn_mtls(&bind, tmp.path(), &certs);
    wait_https_mtls(&format!("{base}/health"), &certs, Duration::from_secs(5));

    // Client with cert signed by an UNTRUSTED CA → reject.
    let client = build_client(&certs, Some(&certs.other_client_pem_bundle));
    let result = client.get(format!("{base}/health")).send();
    assert!(
        result.is_err(),
        "mTLS server MUST reject clients whose cert isn't signed by the trusted CA"
    );
}

#[test]
fn mtls_without_server_tls_rejected() {
    // --mtls-ca-cert without --tls-cert/--tls-key → daemon refuses to start.
    let tmp = TempDir::new().unwrap();
    let certs = make_certs(tmp.path());
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{port}");
    let binary = env!("CARGO_BIN_EXE_tardus-validator");
    let output = Command::new(binary)
        .arg("--bind").arg(&bind)
        .arg("--data-dir").arg(tmp.path())
        .arg("--operator").arg("mtls-misconfig")
        .arg("--mtls-ca-cert").arg(&certs.ca_path)
        .output()
        .expect("spawn");
    assert!(
        !output.status.success(),
        "--mtls-ca-cert without server TLS MUST fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("mtls") || stderr.contains("tls-cert") || stderr.contains("tls-key"),
        "stderr should mention the misconfig: {stderr}"
    );
}
