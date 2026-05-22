//! Real devnet end-to-end test (v1.4.8).
//!
//! Submits actual transactions to Solana devnet against the deployed
//! TARDUS program. Runs the full lifecycle:
//!   1. Bootstrap × 3 (KeysetRegistry, NullifierTree, Vault[denom])
//!      — idempotent on the singleton PDAs (registry / nullifier),
//!        fresh allocation for the per-denom vault
//!   2. RegisterKeyset with a freshly generated mint keypair
//!   3. Issue a coin off-chain (Cp = x·G, sig = mint·schnorr_sign(Cp))
//!   4. Refresh TX with ed25519 precompile pre-instruction
//!   5. Verify on-chain nullifier inserted
//!
//! Marked `#[ignore]` so it never runs in default `cargo test`. To
//! execute:
//!
//! ```sh
//! cargo test -p tardus-program --test devnet_e2e --release -- \
//!     --ignored --nocapture --test-threads=1
//! ```
//!
//! Requires `~/.config/solana/id.json` to hold a wallet with > 0.05
//! SOL on devnet.

#![allow(
    clippy::similar_names,
    clippy::unreadable_literal,
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::doc_overindented_list_items,
    clippy::if_not_else,
    // solana-sdk 2.x deprecates `system_program` in favour of
    // `solana_system_interface`; the latter isn't yet stable as a
    // top-level re-export. Suppressed here pending solana-sdk migration.
    deprecated
)]

use rand::rngs::OsRng;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    ed25519_program,
    instruction::{AccountMeta, Instruction as SolInstruction},
    pubkey::Pubkey,
    signature::{read_keypair_file, Signer},
    system_program, sysvar,
    transaction::Transaction,
};
use std::str::FromStr;
use tardus_core::{
    schnorr_sign, Keypair as TKeypair, PublicKey as TPublicKey, SecretKey as TSecretKey,
};
use tardus_program::{
    instruction::{BootstrapKind, Instruction},
    processor::compute_nullifier,
    state::NullifierSet,
};

const PROGRAM_ID_B58: &str = "AmY1ysgQyCC6CmorXkrNkogBSHmomy4kbsPziAYUx47u";
const RPC_URL: &str = "https://api.devnet.solana.com";
const REGISTRY_SIZE: u32 = 1024;
const NULLIFIER_SIZE: u32 = 8192;

fn keypair_path() -> String {
    std::env::var("SOLANA_KEYPAIR").unwrap_or_else(|_| {
        let home = std::env::var("HOME").expect("HOME env");
        format!("{home}/.config/solana/id.json")
    })
}

fn build_ed25519_precompile_data(
    sig: &tardus_core::Signature,
    pk: &[u8; 32],
    msg: &[u8; 32],
) -> Vec<u8> {
    let mut data = vec![0u8; 16 + 64 + 32 + 32];
    data[0] = 1;
    data[1] = 0;
    data[2..4].copy_from_slice(&16u16.to_le_bytes());
    data[4..6].copy_from_slice(&u16::MAX.to_le_bytes());
    data[6..8].copy_from_slice(&80u16.to_le_bytes());
    data[8..10].copy_from_slice(&u16::MAX.to_le_bytes());
    data[10..12].copy_from_slice(&112u16.to_le_bytes());
    data[12..14].copy_from_slice(&32u16.to_le_bytes());
    data[14..16].copy_from_slice(&u16::MAX.to_le_bytes());
    data[16..48].copy_from_slice(&sig.r);
    data[48..80].copy_from_slice(&sig.s);
    data[80..112].copy_from_slice(pk);
    data[112..144].copy_from_slice(msg);
    data
}

#[tokio::test]
#[ignore = "submits real TXs to devnet — run with --ignored"]
async fn devnet_full_lifecycle() {
    let program_id = Pubkey::from_str(PROGRAM_ID_B58).expect("program id");
    let rpc = RpcClient::new_with_commitment(
        RPC_URL.to_string(),
        CommitmentConfig::confirmed(),
    );

    let payer = read_keypair_file(keypair_path()).expect("read deployer keypair");
    eprintln!("[devnet] payer = {}", payer.pubkey());
    eprintln!("[devnet] program_id = {program_id}");

    let balance_lamports = rpc.get_balance(&payer.pubkey()).await.expect("balance");
    eprintln!(
        "[devnet] payer balance = {:.3} SOL",
        balance_lamports as f64 / 1_000_000_000.0
    );
    assert!(
        balance_lamports > 50_000_000,
        "payer needs > 0.05 SOL on devnet"
    );

    // ============================================================
    // Step 1: Bootstrap singleton PDAs (registry, nullifier).
    //         Idempotent — error 0x0F (already exists) is OK.
    // ============================================================
    let (registry_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"keyset-registry"], &program_id);
    let (nullifier_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"nullifier-tree"], &program_id);
    eprintln!("[devnet] registry_pda = {registry_pda}");
    eprintln!("[devnet] nullifier_pda = {nullifier_pda}");

    let registry_exists = rpc.get_account(&registry_pda).await.is_ok();
    if !registry_exists {
        eprintln!("[devnet] bootstrapping registry...");
        let ix = SolInstruction {
            program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(registry_pda, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data: borsh::to_vec(&Instruction::Bootstrap {
                account_kind: BootstrapKind::KeysetRegistry,
                size: REGISTRY_SIZE,
                denom: 0,
            })
            .unwrap(),
        };
        let bh = rpc.get_latest_blockhash().await.expect("blockhash");
        let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], bh);
        let sig = rpc.send_and_confirm_transaction(&tx).await.expect("bootstrap registry");
        eprintln!("[devnet] bootstrap-registry sig: {sig}");
    } else {
        eprintln!("[devnet] registry already exists, skipping bootstrap");
    }

    let nullifier_exists = rpc.get_account(&nullifier_pda).await.is_ok();
    if !nullifier_exists {
        eprintln!("[devnet] bootstrapping nullifier tree...");
        let ix = SolInstruction {
            program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(nullifier_pda, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data: borsh::to_vec(&Instruction::Bootstrap {
                account_kind: BootstrapKind::NullifierTree,
                size: NULLIFIER_SIZE,
                denom: 0,
            })
            .unwrap(),
        };
        let bh = rpc.get_latest_blockhash().await.expect("blockhash");
        let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], bh);
        let sig = rpc.send_and_confirm_transaction(&tx).await.expect("bootstrap nullifier");
        eprintln!("[devnet] bootstrap-nullifier sig: {sig}");
    } else {
        eprintln!("[devnet] nullifier already exists, skipping bootstrap");
    }

    // ============================================================
    // Step 2: Fresh mint + fresh denom for this test run, then
    //         Bootstrap{Vault} (per-denom PDA — always new).
    // ============================================================
    let mut rng = OsRng;
    let mint = TKeypair::random(&mut rng);
    let denom: u64 = {
        use rand::RngCore;
        // Bias toward small unique-ish denoms in 1M..1B
        1_000_000 + (OsRng.next_u64() % 999_000_000)
    };
    eprintln!("[devnet] test mint joint_pk = {}", hex::encode(mint.public.to_bytes()));
    eprintln!("[devnet] test denom = {denom}");

    let (vault_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"vault", &denom.to_le_bytes()], &program_id);
    eprintln!("[devnet] vault_pda = {vault_pda}");

    let ix = SolInstruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(vault_pda, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: borsh::to_vec(&Instruction::Bootstrap {
            account_kind: BootstrapKind::Vault,
            size: 0,
            denom,
        })
        .unwrap(),
    };
    let bh = rpc.get_latest_blockhash().await.expect("blockhash");
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], bh);
    let sig = rpc.send_and_confirm_transaction(&tx).await.expect("bootstrap vault");
    eprintln!("[devnet] bootstrap-vault sig: {sig}");

    // ============================================================
    // Step 3: RegisterKeyset for the fresh (denom, joint_pk).
    // ============================================================
    let mut keyset_id = [0u8; 33];
    keyset_id[0] = 0x02;
    keyset_id[1..].copy_from_slice(&mint.public.to_bytes());
    let ix = SolInstruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(registry_pda, false),
        ],
        data: borsh::to_vec(&Instruction::RegisterKeyset {
            keyset_id,
            denom,
            joint_pk: mint.public.to_bytes(),
            epoch: 1,
            authorization: vec![],
        })
        .unwrap(),
    };
    let bh = rpc.get_latest_blockhash().await.expect("blockhash");
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], bh);
    let sig = rpc.send_and_confirm_transaction(&tx).await.expect("register keyset");
    eprintln!("[devnet] register-keyset sig: {sig}");

    // ============================================================
    // Step 4: Issue coin off-chain.
    // ============================================================
    let coin_sk = TSecretKey::random(&mut rng);
    let coin_pk = TPublicKey::from_secret(&coin_sk);
    let coin_pk_bytes = coin_pk.to_bytes();
    let coin_sig = schnorr_sign(&mint.secret, &mint.public, &coin_pk_bytes, &mut rng);
    eprintln!("[devnet] issued coin Cp = {}", hex::encode(coin_pk_bytes));

    // ============================================================
    // Step 5: Refresh TX with ed25519 precompile + tardus::Refresh.
    // ============================================================
    let precompile_data =
        build_ed25519_precompile_data(&coin_sig, &mint.public.to_bytes(), &coin_pk_bytes);
    let precompile_ix = SolInstruction {
        program_id: ed25519_program::id(),
        accounts: vec![],
        data: precompile_data,
    };
    let refresh_ix = SolInstruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(registry_pda, false),
            AccountMeta::new(nullifier_pda, false),
            AccountMeta::new_readonly(sysvar::instructions::id(), false),
        ],
        data: borsh::to_vec(&Instruction::Refresh {
            coin_pubkey: coin_pk_bytes,
            coin_signature: coin_sig,
            denom,
        })
        .unwrap(),
    };
    let bh = rpc.get_latest_blockhash().await.expect("blockhash");
    let tx = Transaction::new_signed_with_payer(
        &[precompile_ix, refresh_ix],
        Some(&payer.pubkey()),
        &[&payer],
        bh,
    );
    let sig = rpc.send_and_confirm_transaction(&tx).await.expect("refresh");
    eprintln!("[devnet] REFRESH sig: {sig}");
    eprintln!(
        "[devnet] explorer: https://explorer.solana.com/tx/{sig}?cluster=devnet"
    );

    // ============================================================
    // Step 6: Verify nullifier was inserted on-chain.
    // ============================================================
    let nullifier_account = rpc
        .get_account(&nullifier_pda)
        .await
        .expect("fetch nullifier account post-refresh");
    let recovered: NullifierSet = {
        let mut reader: &[u8] = &nullifier_account.data;
        borsh::BorshDeserialize::deserialize_reader(&mut reader).expect("borsh decode")
    };
    let expected = compute_nullifier(&coin_pk_bytes);
    assert!(
        recovered.contains(&expected),
        "nullifier {} must be present on-chain after Refresh",
        hex::encode(expected)
    );
    eprintln!(
        "[devnet] ✓ nullifier {} confirmed on-chain (set size = {})",
        hex::encode(expected),
        recovered.len()
    );

    let balance_after = rpc.get_balance(&payer.pubkey()).await.expect("balance");
    eprintln!(
        "[devnet] payer balance after: {:.3} SOL (▼ {:.6})",
        balance_after as f64 / 1_000_000_000.0,
        (balance_lamports - balance_after) as f64 / 1_000_000_000.0
    );
}
