//! Integration tests for the program processors (spec §5.3).
//!
//! All tests run pure-Rust without the Solana runtime. The "mint" is
//! a single Keypair standing in for the threshold committee's joint
//! public key — cryptographically equivalent for the on-chain
//! signature verification path.

#![allow(clippy::similar_names, clippy::unreadable_literal)]

use rand::rngs::OsRng;
use tardus_core::{schnorr_sign, Keypair, PublicKey, SecretKey};
use tardus_program::{
    instruction::Instruction,
    pda::{keyset_registry_seeds, nullifier_tree_seeds, vault_seeds},
    processor::{
        compute_nullifier, process_deposit, process_refresh, process_register_keyset,
        process_revoke, process_withdraw,
    },
    state::{KeysetRegistry, KeysetStatus, NullifierSet, Vault, KEYSET_REGISTRY_CAPACITY},
    Error,
};

const DENOM: u64 = 10_000_000; // 0.01 SOL in lamports
const RECIPIENT: [u8; 32] = [0xDD; 32];

// =====================================================================
// Helpers
// =====================================================================

struct TestEnv {
    mint: Keypair,
    registry: KeysetRegistry,
    vault: Vault,
    nullifiers: NullifierSet,
}

fn fresh_env() -> TestEnv {
    let mut rng = OsRng;
    let mint = Keypair::random(&mut rng);
    let mut registry = KeysetRegistry::new();

    // Pre-register a keyset for DENOM with joint_pk = mint pubkey.
    let mut keyset_id = [0u8; 33];
    keyset_id[0] = 0x02;
    keyset_id[1..33].copy_from_slice(&mint.public.to_bytes());

    let ix = Instruction::RegisterKeyset {
        keyset_id,
        denom: DENOM,
        joint_pk: mint.public.to_bytes(),
        epoch: 1,
        authorization: alloc_vec(),
    };
    process_register_keyset(&mut registry, &ix).expect("first register must succeed");

    TestEnv {
        mint,
        registry,
        vault: Vault::new(DENOM),
        nullifiers: NullifierSet::new(),
    }
}

fn alloc_vec() -> Vec<u8> {
    Vec::new()
}

/// Build a fresh coin = (sk, pk, sig) where `sig` is the mint's
/// Schnorr signature over `pk.to_bytes()`.
fn fresh_coin(mint: &Keypair) -> (SecretKey, PublicKey, tardus_core::Signature) {
    let mut rng = OsRng;
    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from_secret(&sk);
    let sig = schnorr_sign(&mint.secret, &mint.public, &pk.to_bytes(), &mut rng);
    (sk, pk, sig)
}

// =====================================================================
// PDA seed sanity
// =====================================================================

#[test]
fn pda_seeds_are_deterministic_and_distinct() {
    let r1 = keyset_registry_seeds();
    let r2 = keyset_registry_seeds();
    let n1 = nullifier_tree_seeds();
    let v1 = vault_seeds(DENOM);
    let v2 = vault_seeds(DENOM);
    let v_other = vault_seeds(DENOM * 2);

    assert_eq!(r1, r2);
    assert_eq!(v1, v2);
    assert_ne!(r1, n1);
    assert_ne!(r1, v1);
    assert_ne!(v1, v_other, "vault seeds must differ across denominations");
}

// =====================================================================
// RegisterKeyset
// =====================================================================

#[test]
fn register_keyset_happy_path() {
    let env = fresh_env();
    assert_eq!(env.registry.entries.len(), 1);
    let entry = &env.registry.entries[0];
    assert_eq!(entry.denom, DENOM);
    assert_eq!(entry.status, KeysetStatus::Active);
}

#[test]
fn register_keyset_duplicate_rejected() {
    let mut env = fresh_env();
    let existing_id = env.registry.entries[0].keyset_id;
    let ix = Instruction::RegisterKeyset {
        keyset_id: existing_id,
        denom: DENOM,
        joint_pk: env.mint.public.to_bytes(),
        epoch: 1,
        authorization: alloc_vec(),
    };
    match process_register_keyset(&mut env.registry, &ix) {
        Err(Error::KeysetAlreadyRegistered) => {}
        other => panic!("expected KeysetAlreadyRegistered, got {other:?}"),
    }
}

// =====================================================================
// Deposit
// =====================================================================

#[test]
fn deposit_happy_path_credits_vault() {
    let mut env = fresh_env();
    let ix = Instruction::Deposit {
        denom: DENOM,
        lamports: DENOM,
    };
    process_deposit(&env.registry, &mut env.vault, &ix).unwrap();
    assert_eq!(env.vault.collateral, DENOM);
}

#[test]
fn deposit_amount_mismatch_rejected() {
    let mut env = fresh_env();
    let ix = Instruction::Deposit {
        denom: DENOM,
        lamports: DENOM - 1,
    };
    match process_deposit(&env.registry, &mut env.vault, &ix) {
        Err(Error::DepositAmountMismatch) => {}
        other => panic!("expected DepositAmountMismatch, got {other:?}"),
    }
}

#[test]
fn deposit_unknown_keyset_rejected() {
    let mut env = fresh_env();
    let mut vault_other = Vault::new(DENOM * 2);
    let ix = Instruction::Deposit {
        denom: DENOM * 2, // no registered keyset for this
        lamports: DENOM * 2,
    };
    match process_deposit(&env.registry, &mut vault_other, &ix) {
        Err(Error::UnknownKeysetId) => {}
        other => panic!("expected UnknownKeysetId, got {other:?}"),
    }
    // env not mutated
    let _ = &mut env;
}

// =====================================================================
// Refresh
// =====================================================================

#[test]
fn refresh_happy_path_inserts_nullifier() {
    let mut env = fresh_env();
    let (_sk, pk, sig) = fresh_coin(&env.mint);
    let ix = Instruction::Refresh {
        coin_pubkey: pk.to_bytes(),
        coin_signature: sig,
        denom: DENOM,
    };
    let nullifier = process_refresh(&env.registry, &mut env.nullifiers, &ix).unwrap();
    assert_eq!(nullifier, compute_nullifier(&pk.to_bytes()));
    assert!(env.nullifiers.contains(&nullifier));
    assert_eq!(env.nullifiers.len(), 1);
}

#[test]
fn refresh_double_spend_rejected() {
    let mut env = fresh_env();
    let (_sk, pk, sig) = fresh_coin(&env.mint);
    let ix = Instruction::Refresh {
        coin_pubkey: pk.to_bytes(),
        coin_signature: sig,
        denom: DENOM,
    };
    // First spend succeeds.
    process_refresh(&env.registry, &mut env.nullifiers, &ix).unwrap();
    // Second spend with same secret must fail.
    match process_refresh(&env.registry, &mut env.nullifiers, &ix) {
        Err(Error::DoubleSpend) => {}
        other => panic!("expected DoubleSpend, got {other:?}"),
    }
}

#[test]
fn refresh_bad_signature_rejected() {
    let mut env = fresh_env();
    let (_sk, pk, mut sig) = fresh_coin(&env.mint);
    // Tamper signature.
    sig.s[0] ^= 0x01;
    let ix = Instruction::Refresh {
        coin_pubkey: pk.to_bytes(),
        coin_signature: sig,
        denom: DENOM,
    };
    match process_refresh(&env.registry, &mut env.nullifiers, &ix) {
        Err(Error::CoinSignatureInvalid) => {}
        other => panic!("expected CoinSignatureInvalid, got {other:?}"),
    }
}

#[test]
fn refresh_revoked_keyset_rejected() {
    let mut env = fresh_env();
    // Revoke the keyset.
    let kid = env.registry.entries[0].keyset_id;
    let ix_revoke = Instruction::Revoke {
        keyset_id: kid,
        authorization: alloc_vec(),
    };
    process_revoke(&mut env.registry, &ix_revoke).unwrap();

    let (_sk, pk, sig) = fresh_coin(&env.mint);
    let ix_refresh = Instruction::Refresh {
        coin_pubkey: pk.to_bytes(),
        coin_signature: sig,
        denom: DENOM,
    };
    // The find_active_for_denom returns None when no active keyset,
    // yielding UnknownKeysetId.
    match process_refresh(&env.registry, &mut env.nullifiers, &ix_refresh) {
        Err(Error::UnknownKeysetId) => {}
        other => panic!("expected UnknownKeysetId (no active), got {other:?}"),
    }
}

// =====================================================================
// Withdraw
// =====================================================================

#[test]
fn withdraw_happy_path_releases_collateral() {
    let mut env = fresh_env();
    // Deposit to fund the vault.
    let ix_dep = Instruction::Deposit {
        denom: DENOM,
        lamports: DENOM,
    };
    process_deposit(&env.registry, &mut env.vault, &ix_dep).unwrap();
    assert_eq!(env.vault.collateral, DENOM);

    let (_sk, pk, sig) = fresh_coin(&env.mint);
    let ix_w = Instruction::Withdraw {
        coin_pubkey: pk.to_bytes(),
        coin_signature: sig,
        denom: DENOM,
        recipient: RECIPIENT,
    };
    let outcome = process_withdraw(&env.registry, &mut env.vault, &mut env.nullifiers, &ix_w)
        .unwrap();
    assert_eq!(outcome.lamports_released, DENOM);
    assert_eq!(outcome.recipient, RECIPIENT);
    assert_eq!(env.vault.collateral, 0);
}

#[test]
fn withdraw_insufficient_vault_rejected() {
    let mut env = fresh_env();
    // No deposit — vault has 0 collateral.
    let (_sk, pk, sig) = fresh_coin(&env.mint);
    let ix_w = Instruction::Withdraw {
        coin_pubkey: pk.to_bytes(),
        coin_signature: sig,
        denom: DENOM,
        recipient: RECIPIENT,
    };
    match process_withdraw(&env.registry, &mut env.vault, &mut env.nullifiers, &ix_w) {
        Err(Error::VaultInsufficientCollateral) => {}
        other => panic!("expected VaultInsufficientCollateral, got {other:?}"),
    }
}

#[test]
fn withdraw_double_spend_rejected() {
    let mut env = fresh_env();
    // Fund vault for 2 withdrawals worth.
    for _ in 0..2 {
        process_deposit(
            &env.registry,
            &mut env.vault,
            &Instruction::Deposit {
                denom: DENOM,
                lamports: DENOM,
            },
        )
        .unwrap();
    }

    let (_sk, pk, sig) = fresh_coin(&env.mint);
    let ix_w = Instruction::Withdraw {
        coin_pubkey: pk.to_bytes(),
        coin_signature: sig,
        denom: DENOM,
        recipient: RECIPIENT,
    };
    // First withdraw succeeds.
    process_withdraw(&env.registry, &mut env.vault, &mut env.nullifiers, &ix_w).unwrap();
    // Second with same coin must fail.
    match process_withdraw(&env.registry, &mut env.vault, &mut env.nullifiers, &ix_w) {
        Err(Error::DoubleSpend) => {}
        other => panic!("expected DoubleSpend, got {other:?}"),
    }
}

#[test]
fn withdraw_after_refresh_with_same_secret_rejected() {
    let mut env = fresh_env();
    process_deposit(
        &env.registry,
        &mut env.vault,
        &Instruction::Deposit {
            denom: DENOM,
            lamports: DENOM,
        },
    )
    .unwrap();

    let (_sk, pk, sig) = fresh_coin(&env.mint);
    let ix_refresh = Instruction::Refresh {
        coin_pubkey: pk.to_bytes(),
        coin_signature: sig,
        denom: DENOM,
    };
    process_refresh(&env.registry, &mut env.nullifiers, &ix_refresh).unwrap();

    let ix_w = Instruction::Withdraw {
        coin_pubkey: pk.to_bytes(),
        coin_signature: sig,
        denom: DENOM,
        recipient: RECIPIENT,
    };
    match process_withdraw(&env.registry, &mut env.vault, &mut env.nullifiers, &ix_w) {
        Err(Error::DoubleSpend) => {}
        other => panic!("expected DoubleSpend (refresh then withdraw same secret), got {other:?}"),
    }
}

// =====================================================================
// Revoke
// =====================================================================

#[test]
fn revoke_happy_path() {
    let mut env = fresh_env();
    let kid = env.registry.entries[0].keyset_id;
    let ix = Instruction::Revoke {
        keyset_id: kid,
        authorization: alloc_vec(),
    };
    process_revoke(&mut env.registry, &ix).unwrap();
    let entry = env.registry.find(&kid).unwrap();
    assert_eq!(entry.status, KeysetStatus::Revoked);
}

#[test]
fn revoke_unknown_keyset_rejected() {
    let mut env = fresh_env();
    let ix = Instruction::Revoke {
        keyset_id: [0u8; 33],
        authorization: alloc_vec(),
    };
    match process_revoke(&mut env.registry, &ix) {
        Err(Error::UnknownKeysetId) => {}
        other => panic!("expected UnknownKeysetId, got {other:?}"),
    }
}

// =====================================================================
// Crown jewel: full lifecycle
// =====================================================================

#[test]
fn full_lifecycle_deposit_refresh_withdraw() {
    let mut env = fresh_env();
    // Step 1: deposit to fund the vault.
    process_deposit(
        &env.registry,
        &mut env.vault,
        &Instruction::Deposit {
            denom: DENOM,
            lamports: DENOM,
        },
    )
    .unwrap();
    assert_eq!(env.vault.collateral, DENOM);

    // Step 2: issue an "old coin" off-chain (simulated by self-signing).
    let (_sk_old, pk_old, sig_old) = fresh_coin(&env.mint);

    // Step 3: refresh the old coin — nullifies it without releasing collateral.
    let nullifier_old = process_refresh(
        &env.registry,
        &mut env.nullifiers,
        &Instruction::Refresh {
            coin_pubkey: pk_old.to_bytes(),
            coin_signature: sig_old,
            denom: DENOM,
        },
    )
    .unwrap();
    assert_eq!(env.vault.collateral, DENOM, "refresh does NOT touch vault");
    assert!(env.nullifiers.contains(&nullifier_old));

    // Step 4: a NEW coin emerges off-chain (the refresh protocol's round 6 output).
    // The new coin's pubkey is independent of the old coin's — but for this on-chain
    // test, we simulate it as a fresh coin (real protocol uses cut-and-choose, etc.).
    let (_sk_new, pk_new, sig_new) = fresh_coin(&env.mint);

    // Step 5: withdraw the new coin — releases vault collateral.
    let outcome = process_withdraw(
        &env.registry,
        &mut env.vault,
        &mut env.nullifiers,
        &Instruction::Withdraw {
            coin_pubkey: pk_new.to_bytes(),
            coin_signature: sig_new,
            denom: DENOM,
            recipient: RECIPIENT,
        },
    )
    .unwrap();
    assert_eq!(outcome.lamports_released, DENOM);
    assert_eq!(env.vault.collateral, 0);
    assert_eq!(env.nullifiers.len(), 2);

    // Try to double-refresh the old coin — must fail.
    let bad = process_refresh(
        &env.registry,
        &mut env.nullifiers,
        &Instruction::Refresh {
            coin_pubkey: pk_old.to_bytes(),
            coin_signature: sig_old,
            denom: DENOM,
        },
    );
    assert!(matches!(bad, Err(Error::DoubleSpend)));
}

#[test]
fn registry_capacity_bound_documented() {
    // Sanity check on the public capacity constant.
    assert_eq!(KEYSET_REGISTRY_CAPACITY, 256);
}
