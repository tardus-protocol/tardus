//! Unit tests for invoice URI parsing and coin store basics.

#![allow(
    clippy::similar_names,
    clippy::unreadable_literal,
    clippy::cast_possible_truncation
)]

use tardus_client::{
    coin_store::{CoinStatus, CoinStore, StoredCoin},
    error::{Error, InvoiceParseError},
    invoice::{Invoice, INVOICE_SCHEME, MEMO_MAX_BYTES},
};

fn fake_pubkey() -> [u8; 32] {
    let mut pk = [0u8; 32];
    for (i, b) in pk.iter_mut().enumerate() {
        *b = (i as u8) ^ 0xAA;
    }
    pk
}

// =====================================================================
// Invoice parse / serialise
// =====================================================================

#[test]
fn invoice_roundtrip_minimal() {
    let inv = Invoice {
        recipient_pubkey: fake_pubkey(),
        denom: 10_000_000,
        relays: vec![],
        memo: None,
    };
    let uri = inv.to_uri();
    assert!(uri.starts_with(INVOICE_SCHEME));
    let parsed = Invoice::parse(&uri).unwrap();
    assert_eq!(inv, parsed);
}

#[test]
fn invoice_roundtrip_full() {
    let inv = Invoice {
        recipient_pubkey: fake_pubkey(),
        denom: 1_000_000_000,
        relays: vec![
            "https://relay-a.example.com/v1".into(),
            "https://relay-b.example.net/v1".into(),
        ],
        memo: Some(b"hello tardus".to_vec()),
    };
    let uri = inv.to_uri();
    let parsed = Invoice::parse(&uri).unwrap();
    assert_eq!(inv, parsed);
}

#[test]
fn invoice_wrong_scheme_rejected() {
    let bad = "bitcoin://abcdef";
    match Invoice::parse(bad) {
        Err(Error::InvalidInvoice(InvoiceParseError::WrongScheme)) => {}
        other => panic!("expected WrongScheme, got {other:?}"),
    }
}

#[test]
fn invoice_missing_denom_rejected() {
    let pk_hex = "00".repeat(32);
    let bad = format!("tardus://{pk_hex}?relay=https://r.example.com");
    match Invoice::parse(&bad) {
        Err(Error::InvalidInvoice(InvoiceParseError::MissingDenom)) => {}
        other => panic!("expected MissingDenom, got {other:?}"),
    }
}

#[test]
fn invoice_invalid_hex_rejected() {
    let bad = "tardus://nothex?denom=100";
    match Invoice::parse(bad) {
        Err(Error::InvalidInvoice(InvoiceParseError::InvalidRecipientHex)) => {}
        other => panic!("expected InvalidRecipientHex, got {other:?}"),
    }
}

#[test]
fn invoice_invalid_denom_rejected() {
    let pk_hex = "00".repeat(32);
    let bad = format!("tardus://{pk_hex}?denom=not_a_number");
    match Invoice::parse(&bad) {
        Err(Error::InvalidInvoice(InvoiceParseError::InvalidDenom)) => {}
        other => panic!("expected InvalidDenom, got {other:?}"),
    }
}

#[test]
fn invoice_memo_too_long_rejected() {
    let pk_hex = "11".repeat(32);
    let long_memo = vec![b'x'; MEMO_MAX_BYTES + 1];
    let inv = Invoice {
        recipient_pubkey: [0x11; 32],
        denom: 1,
        relays: vec![],
        memo: Some(long_memo),
    };
    let uri = inv.to_uri();
    // Sanity: should still encode (just produces a long URI)
    assert!(uri.starts_with(INVOICE_SCHEME));
    let _ = pk_hex;
    // Parser must reject when memo > MEMO_MAX_BYTES
    match Invoice::parse(&uri) {
        Err(Error::InvalidInvoice(InvoiceParseError::MemoTooLong)) => {}
        other => panic!("expected MemoTooLong, got {other:?}"),
    }
}

#[test]
fn invoice_multiple_relays_preserved() {
    let inv = Invoice {
        recipient_pubkey: fake_pubkey(),
        denom: 100,
        relays: vec!["a".into(), "b".into(), "c".into()],
        memo: None,
    };
    let uri = inv.to_uri();
    let parsed = Invoice::parse(&uri).unwrap();
    assert_eq!(parsed.relays.len(), 3);
}

#[test]
fn invoice_unknown_key_ignored() {
    let pk_hex = "22".repeat(32);
    let uri = format!("tardus://{pk_hex}?denom=42&future_field=ignored");
    let parsed = Invoice::parse(&uri).unwrap();
    assert_eq!(parsed.denom, 42);
}

#[test]
fn invoice_uri_format_starts_with_scheme() {
    let inv = Invoice {
        recipient_pubkey: fake_pubkey(),
        denom: 1,
        relays: vec![],
        memo: None,
    };
    assert!(inv.to_uri().starts_with(INVOICE_SCHEME));
}

// =====================================================================
// Coin store
// =====================================================================

fn fake_coin(seed: u8, denom: u64) -> StoredCoin {
    let secret = [seed; 32];
    let pk = [seed.wrapping_add(1); 32];
    let sig = [seed.wrapping_add(2); 64];
    StoredCoin {
        secret_bytes: secret,
        pubkey_bytes: pk,
        signature_bytes: sig,
        denom,
        status: CoinStatus::Active,
        label: None,
    }
}

#[test]
fn coin_store_add_and_find() {
    let mut store = CoinStore::new();
    let coin = fake_coin(1, 1000);
    store.add(coin.clone()).unwrap();
    assert_eq!(store.coins.len(), 1);
    let found = store.find_active(1000).unwrap();
    assert_eq!(found.secret_bytes, coin.secret_bytes);
}

#[test]
fn coin_store_duplicate_rejected() {
    let mut store = CoinStore::new();
    let coin = fake_coin(1, 1000);
    store.add(coin.clone()).unwrap();
    match store.add(coin) {
        Err(Error::DuplicateCoin) => {}
        other => panic!("expected DuplicateCoin, got {other:?}"),
    }
}

#[test]
fn coin_store_status_transitions() {
    let mut store = CoinStore::new();
    let coin = fake_coin(7, 5000);
    let n = coin.nullifier();
    store.add(coin).unwrap();
    assert_eq!(store.coins[0].status, CoinStatus::Active);
    store.mark_in_flight(&n).unwrap();
    assert_eq!(store.coins[0].status, CoinStatus::InFlight);
    store.mark_spent(&n).unwrap();
    assert_eq!(store.coins[0].status, CoinStatus::Spent);
}

#[test]
fn coin_store_balance_excludes_non_active() {
    let mut store = CoinStore::new();
    for i in 0..3 {
        store.add(fake_coin(i, 1000)).unwrap();
    }
    assert_eq!(store.active_balance_for_denom(1000), 3000);

    let n = store.coins[0].nullifier();
    store.mark_spent(&n).unwrap();
    assert_eq!(store.active_balance_for_denom(1000), 2000);
}

#[test]
fn coin_store_borsh_roundtrip() {
    let mut store = CoinStore::new();
    for i in 0..5 {
        store.add(fake_coin(i, 1000)).unwrap();
    }
    let n = store.coins[0].nullifier();
    store.mark_spent(&n).unwrap();

    let bytes = borsh::to_vec(&store).unwrap();
    let recovered: CoinStore = borsh::from_slice(&bytes).unwrap();
    assert_eq!(recovered, store);
}

#[test]
fn coin_store_mark_unknown_rejected() {
    let mut store = CoinStore::new();
    let unknown = [0u8; 32];
    match store.mark_in_flight(&unknown) {
        Err(Error::CoinNotFound) => {}
        other => panic!("expected CoinNotFound, got {other:?}"),
    }
}

#[test]
fn coin_nullifier_is_deterministic() {
    let c = fake_coin(42, 1);
    assert_eq!(c.nullifier(), c.nullifier());
}
