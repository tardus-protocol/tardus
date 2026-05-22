//! Regression test for the on-chain nullifier guard in `refresh_round5`.
//!
//! Spins up a minimal in-process mock Solana RPC server (using `axum`)
//! and calls `verify_nullifier_finalized` directly to confirm:
//!
//! 1. Returns `Ok(())` when the nullifier IS present in the mock
//!    `NullifierSet` account data.
//! 2. Returns `Err(_)` when the nullifier is absent.
//! 3. Returns `Err(_)` when the PDA account does not exist (null value).
//! 4. Returns `Err(_)` when the RPC is unreachable.

use axum::{routing::post, Json, Router};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::net::TcpListener;
use tardus_validator::api::verify_nullifier_finalized;
use tokio::net::TcpListener as TokioTcpListener;

// ── helpers ──────────────────────────────────────────────────────────────────

/// Compute the TARDUS nullifier for a coin pubkey (mirrors processor.rs).
fn compute_nullifier(coin_pubkey: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"TARDUS-nullifier-v1");
    h.update(coin_pubkey);
    let out = h.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    bytes
}

/// Borsh-encode a `BTreeSet<[u8;32]>` as the `NullifierSet` wire format:
/// u32 (LE) count followed by count × 32-byte leaves in sorted order.
fn encode_nullifier_set(leaves: &BTreeSet<[u8; 32]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + leaves.len() * 32);
    let count = leaves.len() as u32;
    out.extend_from_slice(&count.to_le_bytes());
    for leaf in leaves {
        out.extend_from_slice(leaf);
    }
    out
}

/// Pick a free TCP port on localhost.
fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

// ── mock RPC server ───────────────────────────────────────────────────────────

/// Build a one-shot Axum router that responds to `getAccountInfo` with
/// the provided `account_data` bytes (base64-encoded), or with a null
/// value if `account_data` is `None`.
fn mock_rpc_router(account_data: Option<Vec<u8>>) -> Router {
    use axum::response::IntoResponse;
    use base64::Engine as _;

    let handler = move || {
        let account_data = account_data.clone();
        async move {
            let body = match account_data {
                Some(data) => {
                    let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "value": {
                                "data": [b64, "base64"],
                                "executable": false,
                                "lamports": 1_000_000,
                                "owner": "11111111111111111111111111111111",
                                "rentEpoch": 0
                            }
                        }
                    })
                }
                None => serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": { "value": null }
                }),
            };
            Json(body).into_response()
        }
    };

    Router::new().route("/", post(handler))
}

/// Spawn a mock RPC server on `port` and return the URL.
async fn spawn_mock_rpc(port: u16, account_data: Option<Vec<u8>>) -> String {
    let router = mock_rpc_router(account_data);
    let listener = TokioTcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("http://127.0.0.1:{port}")
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// Nullifier IS in the set → guard must pass.
#[tokio::test]
async fn test_nullifier_present_returns_ok() {
    let coin_pubkey = [0x42u8; 32];
    let nullifier = compute_nullifier(&coin_pubkey);

    let mut leaves = BTreeSet::new();
    leaves.insert(nullifier);
    let account_data = encode_nullifier_set(&leaves);

    let port = free_port();
    let rpc_url = spawn_mock_rpc(port, Some(account_data)).await;

    let pda = [0xAAu8; 32]; // arbitrary PDA address for the mock
    let result = verify_nullifier_finalized(&rpc_url, &pda, &coin_pubkey).await;
    assert!(
        result.is_ok(),
        "expected Ok when nullifier is present, got: {result:?}"
    );
}

/// Nullifier is NOT in the set → guard must reject.
#[tokio::test]
async fn test_nullifier_absent_returns_err() {
    let coin_pubkey = [0x42u8; 32];
    // Put a *different* nullifier in the set.
    let other_nullifier = compute_nullifier(&[0xFFu8; 32]);

    let mut leaves = BTreeSet::new();
    leaves.insert(other_nullifier);
    let account_data = encode_nullifier_set(&leaves);

    let port = free_port();
    let rpc_url = spawn_mock_rpc(port, Some(account_data)).await;

    let pda = [0xAAu8; 32];
    let result = verify_nullifier_finalized(&rpc_url, &pda, &coin_pubkey).await;
    assert!(
        result.is_err(),
        "expected Err when nullifier is absent, got Ok"
    );
    let msg = result.unwrap_err();
    assert!(
        msg.contains("not found"),
        "error message should mention 'not found', got: {msg}"
    );
}

/// Empty NullifierSet → guard must reject.
#[tokio::test]
async fn test_empty_nullifier_set_returns_err() {
    let coin_pubkey = [0x11u8; 32];
    let account_data = encode_nullifier_set(&BTreeSet::new());

    let port = free_port();
    let rpc_url = spawn_mock_rpc(port, Some(account_data)).await;

    let pda = [0xAAu8; 32];
    let result = verify_nullifier_finalized(&rpc_url, &pda, &coin_pubkey).await;
    assert!(result.is_err(), "expected Err for empty set, got Ok");
}

/// PDA account does not exist (null value) → guard must reject.
#[tokio::test]
async fn test_pda_account_not_found_returns_err() {
    let coin_pubkey = [0x55u8; 32];

    let port = free_port();
    let rpc_url = spawn_mock_rpc(port, None).await; // null value

    let pda = [0xAAu8; 32];
    let result = verify_nullifier_finalized(&rpc_url, &pda, &coin_pubkey).await;
    assert!(
        result.is_err(),
        "expected Err when PDA account is null, got Ok"
    );
    let msg = result.unwrap_err();
    assert!(
        msg.contains("does not exist") || msg.contains("not been broadcast"),
        "error message should mention missing account, got: {msg}"
    );
}

/// RPC server unreachable → guard must reject (not panic).
#[tokio::test]
async fn test_rpc_unreachable_returns_err() {
    let coin_pubkey = [0x77u8; 32];
    // Use a port that nothing is listening on.
    let rpc_url = "http://127.0.0.1:1"; // port 1 is reserved, always refused
    let pda = [0xAAu8; 32];
    let result = verify_nullifier_finalized(rpc_url, &pda, &coin_pubkey).await;
    assert!(
        result.is_err(),
        "expected Err when RPC is unreachable, got Ok"
    );
}

/// Multiple nullifiers in the set; target is present → guard must pass.
#[tokio::test]
async fn test_nullifier_present_among_many() {
    let coin_pubkey = [0x33u8; 32];
    let nullifier = compute_nullifier(&coin_pubkey);

    let mut leaves = BTreeSet::new();
    // Insert several other nullifiers around the target.
    for i in 0u8..10 {
        leaves.insert(compute_nullifier(&[i; 32]));
    }
    leaves.insert(nullifier);
    let account_data = encode_nullifier_set(&leaves);

    let port = free_port();
    let rpc_url = spawn_mock_rpc(port, Some(account_data)).await;

    let pda = [0xAAu8; 32];
    let result = verify_nullifier_finalized(&rpc_url, &pda, &coin_pubkey).await;
    assert!(
        result.is_ok(),
        "expected Ok when nullifier is present among many, got: {result:?}"
    );
}