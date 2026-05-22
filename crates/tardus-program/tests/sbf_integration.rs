//! End-to-end SVM integration test (v1.4.5).
//!
//! Runs a real Solana transaction through `solana-program-test`:
//! an `ed25519_program` precompile pre-instruction validates a coin
//! signature, then `tardus_program::Refresh` inserts the nullifier.
//! Verifies that the precompile bridge in `ed25519_verifier` works at
//! actual SVM runtime — not just compiles.

#![allow(
    clippy::similar_names,
    clippy::unreadable_literal,
    clippy::doc_markdown,
    clippy::too_many_lines
)]

use rand::rngs::OsRng;
use solana_program_test::{processor, ProgramTest};
use solana_sdk::{
    account::Account,
    ed25519_program,
    instruction::{AccountMeta, Instruction as SolInstruction},
    pubkey::Pubkey,
    signature::Signer,
    sysvar,
    transaction::Transaction,
};
use tardus_core::{
    schnorr_sign, Keypair as TKeypair, PublicKey as TPublicKey, SecretKey as TSecretKey,
};
use tardus_program::{
    instruction::{BootstrapKind, Instruction},
    processor::compute_nullifier,
    state::{KeysetEntry, KeysetRegistry, KeysetStatus, NullifierSet},
};

const DENOM: u64 = 10_000_000;

/// Build the ed25519 precompile instruction data for a single signature
/// whose components are all in this same instruction's data.
fn build_ed25519_precompile_data(
    signature: &tardus_core::Signature,
    pubkey: &[u8; 32],
    message: &[u8; 32],
) -> Vec<u8> {
    let total_len = 16 + 64 + 32 + 32;
    let mut data = vec![0u8; total_len];
    data[0] = 1;
    data[1] = 0;
    // SignatureOffsets
    data[2..4].copy_from_slice(&16u16.to_le_bytes());
    data[4..6].copy_from_slice(&u16::MAX.to_le_bytes());
    data[6..8].copy_from_slice(&80u16.to_le_bytes());
    data[8..10].copy_from_slice(&u16::MAX.to_le_bytes());
    data[10..12].copy_from_slice(&112u16.to_le_bytes());
    data[12..14].copy_from_slice(&32u16.to_le_bytes());
    data[14..16].copy_from_slice(&u16::MAX.to_le_bytes());
    // signature
    data[16..48].copy_from_slice(&signature.r);
    data[48..80].copy_from_slice(&signature.s);
    // pubkey
    data[80..112].copy_from_slice(pubkey);
    // message
    data[112..144].copy_from_slice(message);
    data
}

/// Convert a tardus PublicKey to a Solana Pubkey via raw bytes (same
/// 32-byte ed25519 compression).
fn t_pk_to_sol(pk: &TPublicKey) -> [u8; 32] {
    pk.to_bytes()
}

#[tokio::test]
async fn refresh_via_precompile_real_svm() {
    let mut rng = OsRng;
    let program_id = Pubkey::new_unique();

    // Mint keypair stands in for the threshold committee's joint public key.
    let mint = TKeypair::random(&mut rng);

    // Pre-populate registry with one active keyset for DENOM.
    let mut keyset_id = [0u8; 33];
    keyset_id[0] = 0x02;
    keyset_id[1..].copy_from_slice(&t_pk_to_sol(&mint.public));
    let registry = KeysetRegistry {
        version: 1,
        entries: vec![KeysetEntry {
            keyset_id,
            denom: DENOM,
            joint_pk: t_pk_to_sol(&mint.public),
            epoch: 1,
            status: KeysetStatus::Active,
        }],
    };
    let registry_bytes = borsh::to_vec(&registry).expect("borsh registry");
    let mut registry_data = vec![0u8; 1024];
    registry_data[..registry_bytes.len()].copy_from_slice(&registry_bytes);

    let nullifiers = NullifierSet::new();
    let nullifier_bytes = borsh::to_vec(&nullifiers).expect("borsh nullifiers");
    let mut nullifier_data = vec![0u8; 8192];
    nullifier_data[..nullifier_bytes.len()].copy_from_slice(&nullifier_bytes);

    let (registry_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"keyset-registry"], &program_id);
    let (nullifier_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"nullifier-tree"], &program_id);

    // Set up ProgramTest with our program and pre-populated accounts.
    let mut program_test = ProgramTest::new(
        "tardus_program",
        program_id,
        processor!(tardus_program::entrypoint::process_instruction),
    );
    program_test.add_account(
        registry_pda,
        Account {
            lamports: 10_000_000,
            data: registry_data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );
    program_test.add_account(
        nullifier_pda,
        Account {
            lamports: 10_000_000,
            data: nullifier_data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );

    let (banks_client, payer, recent_blockhash) = program_test.start().await;

    // Issue a coin off-chain: secret + Cp = secret·G + mint signature on Cp.
    let coin_sk = TSecretKey::random(&mut rng);
    let coin_pk = TPublicKey::from_secret(&coin_sk);
    let coin_pk_bytes = coin_pk.to_bytes();
    let coin_sig = schnorr_sign(&mint.secret, &mint.public, &coin_pk_bytes, &mut rng);

    // Build the ed25519 precompile pre-instruction.
    let precompile_data = build_ed25519_precompile_data(
        &coin_sig,
        &t_pk_to_sol(&mint.public),
        &coin_pk_bytes,
    );
    let precompile_ix = SolInstruction {
        program_id: ed25519_program::id(),
        accounts: vec![],
        data: precompile_data,
    };

    // Build the tardus_program::Refresh instruction.
    let refresh_ix_data = borsh::to_vec(&Instruction::Refresh {
        coin_pubkey: coin_pk_bytes,
        coin_signature: coin_sig,
        denom: DENOM,
    })
    .expect("borsh refresh ix");
    let refresh_ix = SolInstruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(registry_pda, false),
            AccountMeta::new(nullifier_pda, false),
            AccountMeta::new_readonly(sysvar::instructions::id(), false),
        ],
        data: refresh_ix_data,
    };

    let mut tx = Transaction::new_with_payer(
        &[precompile_ix, refresh_ix],
        Some(&payer.pubkey()),
    );
    tx.sign(&[&payer], recent_blockhash);

    let meta = banks_client
        .process_transaction_with_metadata(tx)
        .await
        .expect("RPC");
    meta.result.expect("ed25519 precompile + Refresh TX must succeed");
    let cu = meta.metadata.as_ref().map_or(0, |m| m.compute_units_consumed);
    eprintln!("[CU] refresh_via_precompile_real_svm: {cu} compute units (spec §5.4 estimate: ~280k)");

    // Inspect the nullifier set after the TX: it should contain compute_nullifier(coin_pk_bytes).
    let nullifier_account = banks_client
        .get_account(nullifier_pda)
        .await
        .expect("RPC")
        .expect("nullifier account exists");

    let recovered: NullifierSet = {
        let mut reader: &[u8] = &nullifier_account.data;
        borsh::BorshDeserialize::deserialize_reader(&mut reader)
            .expect("borsh decode nullifiers")
    };
    let expected = compute_nullifier(&coin_pk_bytes);
    assert!(
        recovered.contains(&expected),
        "nullifier must be inserted by Refresh"
    );
    assert_eq!(recovered.len(), 1);
}

#[tokio::test]
async fn withdraw_via_precompile_real_svm() {
    let mut rng = OsRng;
    let program_id = Pubkey::new_unique();
    let mint = TKeypair::random(&mut rng);

    // Pre-populated state
    let mut keyset_id = [0u8; 33];
    keyset_id[0] = 0x02;
    keyset_id[1..].copy_from_slice(&t_pk_to_sol(&mint.public));
    let registry = KeysetRegistry {
        version: 1,
        entries: vec![KeysetEntry {
            keyset_id,
            denom: DENOM,
            joint_pk: t_pk_to_sol(&mint.public),
            epoch: 1,
            status: KeysetStatus::Active,
        }],
    };
    let registry_bytes = borsh::to_vec(&registry).unwrap();
    let mut registry_data = vec![0u8; 1024];
    registry_data[..registry_bytes.len()].copy_from_slice(&registry_bytes);

    let nullifiers = NullifierSet::new();
    let nb = borsh::to_vec(&nullifiers).unwrap();
    let mut nullifier_data = vec![0u8; 8192];
    nullifier_data[..nb.len()].copy_from_slice(&nb);

    let (registry_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"keyset-registry"], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(
        &[b"tardus", b"vault", &DENOM.to_le_bytes()],
        &program_id,
    );
    let (nullifier_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"nullifier-tree"], &program_id);

    let recipient_pubkey = Pubkey::new_unique();
    let vault_initial_lamports: u64 = 100_000_000;

    let mut program_test = ProgramTest::new(
        "tardus_program",
        program_id,
        processor!(tardus_program::entrypoint::process_instruction),
    );
    program_test.add_account(
        registry_pda,
        Account {
            lamports: 10_000_000,
            data: registry_data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );
    program_test.add_account(
        nullifier_pda,
        Account {
            lamports: 10_000_000,
            data: nullifier_data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );
    // Vault PDA is a system-owned account holding lamport collateral.
    program_test.add_account(
        vault_pda,
        Account {
            lamports: vault_initial_lamports,
            data: vec![],
            owner: solana_sdk::system_program::id(),
            executable: false,
            rent_epoch: 0,
        },
    );

    let (banks_client, payer, recent_blockhash) = program_test.start().await;

    // Issue coin off-chain
    let coin_sk = TSecretKey::random(&mut rng);
    let coin_pk = TPublicKey::from_secret(&coin_sk);
    let coin_pk_bytes = coin_pk.to_bytes();
    let coin_sig = schnorr_sign(&mint.secret, &mint.public, &coin_pk_bytes, &mut rng);

    // ed25519 precompile
    let precompile_data =
        build_ed25519_precompile_data(&coin_sig, &t_pk_to_sol(&mint.public), &coin_pk_bytes);
    let precompile_ix = SolInstruction {
        program_id: ed25519_program::id(),
        accounts: vec![],
        data: precompile_data,
    };

    // Withdraw
    let withdraw_data = borsh::to_vec(&Instruction::Withdraw {
        coin_pubkey: coin_pk_bytes,
        coin_signature: coin_sig,
        denom: DENOM,
        recipient: recipient_pubkey.to_bytes(),
    })
    .unwrap();
    let withdraw_ix = SolInstruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(registry_pda, false),
            AccountMeta::new(vault_pda, false),
            AccountMeta::new(nullifier_pda, false),
            AccountMeta::new(recipient_pubkey, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(sysvar::instructions::id(), false),
        ],
        data: withdraw_data,
    };

    let mut tx = Transaction::new_with_payer(
        &[precompile_ix, withdraw_ix],
        Some(&payer.pubkey()),
    );
    tx.sign(&[&payer], recent_blockhash);

    let meta = banks_client
        .process_transaction_with_metadata(tx)
        .await
        .expect("RPC");
    meta.result.expect("ed25519 precompile + Withdraw TX must succeed");
    let cu = meta.metadata.as_ref().map_or(0, |m| m.compute_units_consumed);
    eprintln!("[CU] withdraw_via_precompile_real_svm: {cu} compute units (spec §5.4 estimate: ~220k)");

    // Vault decreased by DENOM
    let vault_account = banks_client
        .get_account(vault_pda)
        .await
        .unwrap()
        .expect("vault still exists");
    assert_eq!(
        vault_account.lamports,
        vault_initial_lamports - DENOM,
        "vault collateral must decrease by DENOM after withdraw"
    );

    // Recipient received DENOM
    let recipient_account = banks_client
        .get_account(recipient_pubkey)
        .await
        .unwrap()
        .expect("recipient account created");
    assert_eq!(
        recipient_account.lamports, DENOM,
        "recipient must receive exactly DENOM lamports"
    );

    // Nullifier inserted
    let nullifier_account = banks_client.get_account(nullifier_pda).await.unwrap().unwrap();
    let recovered: NullifierSet = {
        let mut reader: &[u8] = &nullifier_account.data;
        borsh::BorshDeserialize::deserialize_reader(&mut reader).unwrap()
    };
    let expected = compute_nullifier(&coin_pk_bytes);
    assert!(recovered.contains(&expected));
}

#[tokio::test]
async fn register_keyset_real_svm() {
    let mut rng = OsRng;
    let program_id = Pubkey::new_unique();
    let mint = TKeypair::random(&mut rng);

    // Empty registry account: data all zeros means "empty registry"
    let registry_data = vec![0u8; 1024];
    let (registry_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"keyset-registry"], &program_id);

    let mut program_test = ProgramTest::new(
        "tardus_program",
        program_id,
        processor!(tardus_program::entrypoint::process_instruction),
    );
    program_test.add_account(
        registry_pda,
        Account {
            lamports: 10_000_000,
            data: registry_data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );

    let (banks_client, payer, recent_blockhash) = program_test.start().await;

    let mut keyset_id = [0u8; 33];
    keyset_id[0] = 0x02;
    keyset_id[1..].copy_from_slice(&t_pk_to_sol(&mint.public));

    let register_data = borsh::to_vec(&Instruction::RegisterKeyset {
        keyset_id,
        denom: DENOM,
        joint_pk: t_pk_to_sol(&mint.public),
        epoch: 1,
        authorization: vec![],
    })
    .unwrap();
    let register_ix = SolInstruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(registry_pda, false),
        ],
        data: register_data,
    };

    let mut tx = Transaction::new_with_payer(&[register_ix], Some(&payer.pubkey()));
    tx.sign(&[&payer], recent_blockhash);

    let meta = banks_client
        .process_transaction_with_metadata(tx)
        .await
        .expect("RPC");
    meta.result.expect("RegisterKeyset TX must succeed");
    let cu = meta.metadata.as_ref().map_or(0, |m| m.compute_units_consumed);
    eprintln!("[CU] register_keyset_real_svm: {cu} compute units (spec §5.4 estimate: ~90k)");

    let registry_account = banks_client
        .get_account(registry_pda)
        .await
        .unwrap()
        .expect("registry exists");
    let recovered: KeysetRegistry = {
        let mut reader: &[u8] = &registry_account.data;
        borsh::BorshDeserialize::deserialize_reader(&mut reader).unwrap()
    };
    assert_eq!(recovered.entries.len(), 1);
    assert_eq!(recovered.entries[0].denom, DENOM);
    assert_eq!(recovered.entries[0].status, KeysetStatus::Active);
    assert_eq!(recovered.entries[0].joint_pk, t_pk_to_sol(&mint.public));
}

#[tokio::test]
async fn bootstrap_creates_registry_nullifier_and_vault() {
    let program_id = Pubkey::new_unique();
    let denom = DENOM;

    let (registry_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"keyset-registry"], &program_id);
    let (nullifier_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"nullifier-tree"], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(
        &[b"tardus", b"vault", &denom.to_le_bytes()],
        &program_id,
    );

    let mut program_test = ProgramTest::new(
        "tardus_program",
        program_id,
        processor!(tardus_program::entrypoint::process_instruction),
    );
    program_test.prefer_bpf(true);
    // No pre-populated PDAs: Bootstrap must allocate them.

    let (banks_client, payer, recent_blockhash) = program_test.start().await;

    let make_ix = |kind: BootstrapKind, size: u32, denom: u64, target: Pubkey| SolInstruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(target, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
        data: borsh::to_vec(&Instruction::Bootstrap {
            account_kind: kind,
            size,
            denom,
        })
        .unwrap(),
    };

    // Bootstrap all three account types in a single TX.
    let ixs = vec![
        make_ix(BootstrapKind::KeysetRegistry, 1024, 0, registry_pda),
        make_ix(BootstrapKind::NullifierTree, 8192, 0, nullifier_pda),
        make_ix(BootstrapKind::Vault, 0, denom, vault_pda),
    ];
    let mut tx = Transaction::new_with_payer(&ixs, Some(&payer.pubkey()));
    tx.sign(&[&payer], recent_blockhash);

    let meta = banks_client
        .process_transaction_with_metadata(tx)
        .await
        .expect("RPC");
    meta.result.expect("Bootstrap TX must succeed");
    let cu = meta.metadata.as_ref().map_or(0, |m| m.compute_units_consumed);
    eprintln!("[CU] bootstrap_3x: {cu} compute units (3 PDAs in one TX)");

    // Verify all three accounts exist with the expected properties.
    let registry = banks_client
        .get_account(registry_pda)
        .await
        .unwrap()
        .expect("registry PDA created");
    assert_eq!(registry.owner, program_id);
    assert_eq!(registry.data.len(), 1024);
    assert!(registry.lamports > 0);

    let nullifier = banks_client
        .get_account(nullifier_pda)
        .await
        .unwrap()
        .expect("nullifier PDA created");
    assert_eq!(nullifier.owner, program_id);
    assert_eq!(nullifier.data.len(), 8192);

    let vault = banks_client
        .get_account(vault_pda)
        .await
        .unwrap()
        .expect("vault PDA created");
    assert_eq!(vault.owner, solana_sdk::system_program::id());
    assert_eq!(vault.data.len(), 0);

    // Idempotency: second Bootstrap for the registry must error with
    // ERR_ACCOUNT_ALREADY_EXISTS (custom = 15).
    let recent_blockhash_2 = banks_client
        .get_latest_blockhash()
        .await
        .expect("blockhash");
    let dup_ix = make_ix(BootstrapKind::KeysetRegistry, 1024, 0, registry_pda);
    let mut tx2 = Transaction::new_with_payer(&[dup_ix], Some(&payer.pubkey()));
    tx2.sign(&[&payer], recent_blockhash_2);
    let dup_outcome = banks_client.process_transaction(tx2).await;
    assert!(
        dup_outcome.is_err(),
        "second Bootstrap MUST fail when account already exists"
    );
}

#[tokio::test]
async fn refresh_without_precompile_pre_instruction_rejected() {
    let mut rng = OsRng;
    let program_id = Pubkey::new_unique();
    let mint = TKeypair::random(&mut rng);
    let mut keyset_id = [0u8; 33];
    keyset_id[0] = 0x02;
    keyset_id[1..].copy_from_slice(&t_pk_to_sol(&mint.public));
    let registry = KeysetRegistry {
        version: 1,
        entries: vec![KeysetEntry {
            keyset_id,
            denom: DENOM,
            joint_pk: t_pk_to_sol(&mint.public),
            epoch: 1,
            status: KeysetStatus::Active,
        }],
    };
    let registry_bytes = borsh::to_vec(&registry).unwrap();
    let mut registry_data = vec![0u8; 1024];
    registry_data[..registry_bytes.len()].copy_from_slice(&registry_bytes);
    let nullifiers = NullifierSet::new();
    let mut nullifier_data = vec![0u8; 8192];
    let nb = borsh::to_vec(&nullifiers).unwrap();
    nullifier_data[..nb.len()].copy_from_slice(&nb);
    let (registry_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"keyset-registry"], &program_id);
    let (nullifier_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"nullifier-tree"], &program_id);

    let mut program_test = ProgramTest::new(
        "tardus_program",
        program_id,
        processor!(tardus_program::entrypoint::process_instruction),
    );
    program_test.add_account(
        registry_pda,
        Account {
            lamports: 10_000_000,
            data: registry_data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );
    program_test.add_account(
        nullifier_pda,
        Account {
            lamports: 10_000_000,
            data: nullifier_data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );

    let (banks_client, payer, recent_blockhash) = program_test.start().await;

    let coin_sk = TSecretKey::random(&mut rng);
    let coin_pk = TPublicKey::from_secret(&coin_sk);
    let coin_pk_bytes = coin_pk.to_bytes();
    let coin_sig = schnorr_sign(&mint.secret, &mint.public, &coin_pk_bytes, &mut rng);

    let refresh_ix_data = borsh::to_vec(&Instruction::Refresh {
        coin_pubkey: coin_pk_bytes,
        coin_signature: coin_sig,
        denom: DENOM,
    })
    .unwrap();
    let refresh_ix = SolInstruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(registry_pda, false),
            AccountMeta::new(nullifier_pda, false),
            AccountMeta::new_readonly(sysvar::instructions::id(), false),
        ],
        data: refresh_ix_data,
    };

    // NO ed25519 precompile pre-instruction — Refresh must reject.
    let mut tx = Transaction::new_with_payer(&[refresh_ix], Some(&payer.pubkey()));
    tx.sign(&[&payer], recent_blockhash);

    let outcome = banks_client.process_transaction(tx).await;
    assert!(
        outcome.is_err(),
        "Refresh without preceding precompile MUST fail"
    );
}
