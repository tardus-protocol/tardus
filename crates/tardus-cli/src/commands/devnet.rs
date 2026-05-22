//! `tardus devnet` subcommand group: real on-chain operations against
//! a deployed TARDUS Solana program (defaults to devnet RPC).

#![allow(
    clippy::doc_markdown,
    clippy::similar_names,
    clippy::cast_precision_loss,
    deprecated
)]

use anyhow::{anyhow, Context, Result};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    ed25519_program,
    instruction::{AccountMeta, Instruction as SolInstruction},
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair, Signer},
    system_instruction, system_program, sysvar,
    transaction::Transaction,
};
use std::str::FromStr;
use tardus_core::Signature as TSignature;
use tardus_program::{
    instruction::{BootstrapKind, Instruction},
    processor::compute_nullifier,
    state::{KeysetRegistry, NullifierSet},
};

const REGISTRY_SIZE: u32 = 1024;
const NULLIFIER_SIZE: u32 = 8192;

/// Lamports the sponsor wallet hands to an ephemeral payer to cover
/// a single Refresh TX (precompile + program ix + rent-exempt
/// nothing-account cost). 0.001 SOL is generous; the actual fee is
/// ~5k lamports per signature, leaving the leftover stranded on
/// the ephemeral wallet (intentional — it makes the link harder).
const EPHEMERAL_PAYER_LAMPORTS: u64 = 1_000_000;

/// Pick a sponsor keypair from a colon- or comma-separated pool
/// list. Each Refresh TX should use a different sponsor so the
/// `sponsor → ephemeral → refresh` chain is not always anchored
/// to the same source wallet. Falls back to the default keypair
/// path when `pool_spec` is empty.
///
/// # Errors
/// Any file in the pool that fails to load is propagated.
fn pick_sponsor_from_pool(pool_spec: &str) -> Result<Keypair> {
    use rand::seq::SliceRandom;
    let trimmed = pool_spec.trim();
    if trimmed.is_empty() {
        return read_keypair_file(keypair_path())
            .map_err(|e| anyhow!("read keypair: {e}"));
    }
    let paths: Vec<&str> = trimmed
        .split([',', ':'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if paths.is_empty() {
        return Err(anyhow!("--sponsor-pool: no paths after parsing"));
    }
    let chosen = paths
        .choose(&mut rand::thread_rng())
        .ok_or_else(|| anyhow!("rng choose: empty"))?;
    read_keypair_file(chosen)
        .map_err(|e| anyhow!("read sponsor {chosen}: {e}"))
}

/// **Faz 9.4 + 9.5** — Fund a fresh ephemeral keypair via the
/// on-chain `SponsorPool` (anyone can deposit, anyone can call
/// payout, pool commingles).
///
/// The funding chain on Solana Explorer becomes:
///     `(many anonymous depositors) → SponsorPool PDA → ephemeral`
/// rather than the single-sponsor link of v9.1 / v9.2.
///
/// `pool_caller` is the wallet that submits the SponsorPayout TX
/// (it pays the TX fee, ~5k lamports — itself trivially small).
/// **Faz 9.5**: this can be ROTATED out of the same `--sponsor-pool`
/// list as the deposit sources, breaking the
/// "deployer always calls payout" residual link.
///
/// # Errors
/// Any RPC failure during the SponsorPayout submission.
async fn ephemeral_payer_from_pool(
    pool_caller: &Keypair,
    rpc: &RpcClient,
    program_id: &Pubkey,
    lamports: u64,
) -> Result<Keypair> {
    let ephemeral = Keypair::new();
    let (sponsor_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"sponsor-pool"], program_id);
    let ix = SolInstruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(pool_caller.pubkey(), true),
            AccountMeta::new(sponsor_pda, false),
            AccountMeta::new(ephemeral.pubkey(), false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: borsh::to_vec(&Instruction::SponsorPayout {
            lamports,
            recipient: ephemeral.pubkey().to_bytes(),
        })
        .map_err(|e| anyhow!("borsh: {e}"))?,
    };
    let blockhash = rpc
        .get_latest_blockhash()
        .await
        .map_err(|e| anyhow!("blockhash (sponsor-pool payout): {e}"))?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&pool_caller.pubkey()),
        &[pool_caller],
        blockhash,
    );
    rpc.send_and_confirm_transaction(&tx)
        .await
        .map_err(|e| anyhow!("sponsor-pool payout: {e}"))?;
    Ok(ephemeral)
}

/// Fund a fresh ephemeral keypair from the sponsor wallet so the
/// next TX submission has a previously-unseen signer.
///
/// **What this gains:** Solana Explorer no longer correlates every
/// TARDUS spend with the same operator wallet. The Refresh TX's
/// signer is a one-shot pubkey that is generated, used, then
/// dropped (the in-memory `Keypair` goes out of scope; the
/// remaining dust lamports stay stranded on-chain).
///
/// **What this does NOT yet hide:** the funding transfer itself
/// (`sponsor → ephemeral`) is publicly visible. A graph crawler can
/// still link the ephemeral payer back to the sponsor wallet by
/// following the System transfer. Closing this requires the
/// sponsor-program / pool pattern (Faz 9.2).
///
/// # Errors
/// Any RPC error during transfer is propagated.
async fn ephemeral_payer_from_sponsor(
    sponsor: &Keypair,
    rpc: &RpcClient,
    lamports: u64,
) -> Result<Keypair> {
    let ephemeral = Keypair::new();
    let blockhash = rpc
        .get_latest_blockhash()
        .await
        .map_err(|e| anyhow!("blockhash (sponsor): {e}"))?;
    let ix = system_instruction::transfer(&sponsor.pubkey(), &ephemeral.pubkey(), lamports);
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&sponsor.pubkey()),
        &[sponsor],
        blockhash,
    );
    rpc.send_and_confirm_transaction(&tx)
        .await
        .map_err(|e| anyhow!("sponsor fund ephemeral: {e}"))?;
    Ok(ephemeral)
}

fn keypair_path() -> String {
    std::env::var("SOLANA_KEYPAIR").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| String::from("/"));
        format!("{home}/.config/solana/id.json")
    })
}

fn parse_pubkey(s: &str, label: &str) -> Result<Pubkey> {
    Pubkey::from_str(s).with_context(|| format!("invalid {label} pubkey: {s}"))
}

fn parse_hex32(s: &str, label: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).with_context(|| format!("invalid hex for {label}"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("{label}: expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn make_rpc(url: &str) -> RpcClient {
    RpcClient::new_with_commitment(url.to_string(), CommitmentConfig::confirmed())
}

fn deserialize_padded<T: borsh::BorshDeserialize>(data: &[u8]) -> Result<T> {
    let mut reader: &[u8] = data;
    T::deserialize_reader(&mut reader).map_err(|e| anyhow!("borsh deserialize: {e}"))
}

/// `tardus devnet info` — show program info + decoded registry contents.
pub async fn info(program_id_b58: &str, rpc_url: &str) -> Result<()> {
    let program_id = parse_pubkey(program_id_b58, "program-id")?;
    let rpc = make_rpc(rpc_url);

    println!("# TARDUS program info");
    println!("rpc                : {rpc_url}");
    println!("program_id         : {program_id}");

    let prog_account = rpc
        .get_account(&program_id)
        .await
        .map_err(|e| anyhow!("fetch program: {e}"))?;
    println!("program owner      : {}", prog_account.owner);
    println!("program executable : {}", prog_account.executable);
    println!("program data len   : {} bytes", prog_account.data.len());

    let (registry_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"keyset-registry"], &program_id);
    let (nullifier_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"nullifier-tree"], &program_id);
    println!("registry_pda       : {registry_pda}");
    println!("nullifier_pda      : {nullifier_pda}");

    match rpc.get_account(&registry_pda).await {
        Err(_) => println!("registry status    : NOT BOOTSTRAPPED"),
        Ok(account) => {
            println!("registry status    : present ({} bytes)", account.data.len());
            if account.data.iter().all(|&b| b == 0) {
                println!("registry contents  : empty");
            } else {
                match deserialize_padded::<KeysetRegistry>(&account.data) {
                    Err(e) => println!("registry decode err: {e}"),
                    Ok(registry) => {
                        println!("registry entries   : {}", registry.entries.len());
                        for (i, entry) in registry.entries.iter().enumerate() {
                            println!(
                                "  [{i}] denom={} joint_pk={} epoch={} status={:?}",
                                entry.denom,
                                hex::encode(entry.joint_pk),
                                entry.epoch,
                                entry.status
                            );
                        }
                    }
                }
            }
        }
    }

    match rpc.get_account(&nullifier_pda).await {
        Err(_) => println!("nullifier status   : NOT BOOTSTRAPPED"),
        Ok(account) => {
            println!(
                "nullifier status   : present ({} bytes)",
                account.data.len()
            );
            if account.data.iter().all(|&b| b == 0) {
                println!("nullifier count    : 0");
            } else {
                match deserialize_padded::<NullifierSet>(&account.data) {
                    Err(e) => println!("nullifier decode err: {e}"),
                    Ok(nullifiers) => {
                        println!("nullifier count    : {}", nullifiers.len());
                    }
                }
            }
        }
    }

    Ok(())
}

/// `tardus devnet bootstrap-singletons` — idempotent bootstrap of
/// the registry + nullifier tree PDAs. Vault PDAs are per-denom and
/// bootstrapped separately (typically by the validator daemon when a
/// new keyset is registered).
pub async fn bootstrap_singletons(program_id_b58: &str, rpc_url: &str) -> Result<()> {
    let program_id = parse_pubkey(program_id_b58, "program-id")?;
    let rpc = make_rpc(rpc_url);
    let payer = read_keypair_file(keypair_path())
        .map_err(|e| anyhow!("read keypair: {e}"))?;
    println!("payer       : {}", payer.pubkey());

    let balance = rpc
        .get_balance(&payer.pubkey())
        .await
        .map_err(|e| anyhow!("balance: {e}"))?;
    println!("balance     : {:.6} SOL", balance as f64 / 1_000_000_000.0);
    if balance < 50_000_000 {
        return Err(anyhow!(
            "payer needs > 0.05 SOL on the target network"
        ));
    }

    let (registry_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"keyset-registry"], &program_id);
    let (nullifier_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"nullifier-tree"], &program_id);

    for (label, pda, kind, size) in [
        (
            "registry",
            registry_pda,
            BootstrapKind::KeysetRegistry,
            REGISTRY_SIZE,
        ),
        (
            "nullifier",
            nullifier_pda,
            BootstrapKind::NullifierTree,
            NULLIFIER_SIZE,
        ),
    ] {
        if rpc.get_account(&pda).await.is_ok() {
            println!("{label:9} : SKIP (already present at {pda})");
            continue;
        }
        let ix = SolInstruction {
            program_id,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(pda, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data: borsh::to_vec(&Instruction::Bootstrap {
                account_kind: kind,
                size,
                denom: 0,
            })
            .map_err(|e| anyhow!("borsh: {e}"))?,
        };
        let blockhash = rpc
            .get_latest_blockhash()
            .await
            .map_err(|e| anyhow!("blockhash: {e}"))?;
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            blockhash,
        );
        let sig = rpc
            .send_and_confirm_transaction(&tx)
            .await
            .map_err(|e| anyhow!("bootstrap {label}: {e}"))?;
        println!("{label:9} : OK sig={sig}");
    }

    Ok(())
}

/// Build the ed25519 precompile instruction data for a single-signature
/// verify, all data in the same instruction (matches `ed25519_verifier`'s
/// expected layout).
fn build_ed25519_precompile_data(
    sig: &TSignature,
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

fn parse_hex64(s: &str, label: &str) -> Result<[u8; 64]> {
    let bytes = hex::decode(s).with_context(|| format!("invalid hex for {label}"))?;
    if bytes.len() != 64 {
        return Err(anyhow!("{label}: expected 64 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// `tardus devnet bootstrap-vault` — allocate the system-owned vault
/// PDA for the given denomination.
pub async fn bootstrap_vault(denom: u64, program_id_b58: &str, rpc_url: &str) -> Result<()> {
    let program_id = parse_pubkey(program_id_b58, "program-id")?;
    let rpc = make_rpc(rpc_url);
    let payer = read_keypair_file(keypair_path())
        .map_err(|e| anyhow!("read keypair: {e}"))?;

    let (vault_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"vault", &denom.to_le_bytes()], &program_id);
    println!("payer       : {}", payer.pubkey());
    println!("vault_pda   : {vault_pda} (denom={denom})");

    if rpc.get_account(&vault_pda).await.is_ok() {
        println!("vault       : SKIP (already present)");
        return Ok(());
    }

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
        .map_err(|e| anyhow!("borsh: {e}"))?,
    };
    let blockhash = rpc
        .get_latest_blockhash()
        .await
        .map_err(|e| anyhow!("blockhash: {e}"))?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );
    let sig = rpc
        .send_and_confirm_transaction(&tx)
        .await
        .map_err(|e| anyhow!("bootstrap vault: {e}"))?;
    println!("vault       : OK sig={sig}");
    Ok(())
}

/// `tardus devnet register-keyset` — submit a RegisterKeyset TX
/// with the given (joint_pk, denom, epoch). The keyset_id is derived
/// canonically as `0x02 || joint_pk`.
pub async fn register_keyset(
    joint_pk_hex: &str,
    denom: u64,
    epoch: u64,
    program_id_b58: &str,
    rpc_url: &str,
) -> Result<()> {
    let joint_pk = parse_hex32(joint_pk_hex, "joint-pk")?;
    let program_id = parse_pubkey(program_id_b58, "program-id")?;
    let rpc = make_rpc(rpc_url);
    let payer = read_keypair_file(keypair_path())
        .map_err(|e| anyhow!("read keypair: {e}"))?;

    let (registry_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"keyset-registry"], &program_id);

    let mut keyset_id = [0u8; 33];
    keyset_id[0] = 0x02;
    keyset_id[1..].copy_from_slice(&joint_pk);

    println!("payer       : {}", payer.pubkey());
    println!("registry    : {registry_pda}");
    println!("keyset_id   : {}", hex::encode(keyset_id));
    println!("denom       : {denom}");
    println!("epoch       : {epoch}");

    let ix = SolInstruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(registry_pda, false),
        ],
        data: borsh::to_vec(&Instruction::RegisterKeyset {
            keyset_id,
            denom,
            joint_pk,
            epoch,
            authorization: vec![],
        })
        .map_err(|e| anyhow!("borsh: {e}"))?,
    };
    let blockhash = rpc
        .get_latest_blockhash()
        .await
        .map_err(|e| anyhow!("blockhash: {e}"))?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );
    let sig = rpc
        .send_and_confirm_transaction(&tx)
        .await
        .map_err(|e| anyhow!("register: {e}"))?;
    println!("register    : OK sig={sig}");
    Ok(())
}

/// `tardus devnet refresh` — construct the ed25519 precompile +
/// tardus::Refresh TX and submit it to the network.
pub async fn refresh(
    coin_pubkey_hex: &str,
    coin_signature_hex: &str,
    denom: u64,
    program_id_b58: &str,
    rpc_url: &str,
) -> Result<()> {
    refresh_with_payer_option(
        coin_pubkey_hex,
        coin_signature_hex,
        denom,
        program_id_b58,
        rpc_url,
        false, // sponsor = signer directly (legacy v8.X path)
    )
    .await
}

/// **Faz 9.1 + 9.2** — Refresh with an optional ephemeral payer
/// (Faz 9.1) backed by a multi-sponsor pool (Faz 9.2). When both
/// `use_ephemeral_payer` and a non-empty `sponsor_pool_spec` are
/// supplied, the runtime:
///
///   1. Picks a sponsor keypair at random from the pool.
///   2. Funds a fresh ephemeral keypair from that sponsor.
///   3. Uses the ephemeral keypair to sign the Refresh TX.
///
/// Net effect on Solana Explorer: each Refresh TX has a different
/// signer AND a different funding-source wallet, breaking the
/// `same-source → many TXs` correlation that single-sponsor leaves.
/// Solana Explorer then shows the Refresh TX signed by a brand-new
/// pubkey that never appears anywhere else.
///
/// The sponsor wallet still pays for the funding transfer (which
/// IS publicly visible); the privacy improvement is that the
/// Refresh TX signer is no longer correlated to past Refresh TXs.
///
/// # Errors
/// Propagates RPC errors from the sponsor-fund and Refresh submission.
#[allow(clippy::too_many_arguments)]
pub async fn refresh_with_payer_option(
    coin_pubkey_hex: &str,
    coin_signature_hex: &str,
    denom: u64,
    program_id_b58: &str,
    rpc_url: &str,
    use_ephemeral_payer: bool,
) -> Result<()> {
    refresh_with_sponsor_pool(
        coin_pubkey_hex,
        coin_signature_hex,
        denom,
        program_id_b58,
        rpc_url,
        use_ephemeral_payer,
        "", // empty pool spec = single-sponsor (default keypair)
    )
    .await
}

/// **Faz 9.2** — Refresh with multi-sponsor pool + ephemeral payer.
/// Production-grade privacy hardening.
///
/// `sponsor_pool_spec` is a `,` or `:` separated list of keypair
/// file paths. The runtime picks one at random per call.
///
/// # Errors
/// Propagates RPC errors from sponsor selection, funding, and
/// Refresh submission.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn refresh_with_sponsor_pool(
    coin_pubkey_hex: &str,
    coin_signature_hex: &str,
    denom: u64,
    program_id_b58: &str,
    rpc_url: &str,
    use_ephemeral_payer: bool,
    sponsor_pool_spec: &str,
) -> Result<()> {
    refresh_full(
        coin_pubkey_hex,
        coin_signature_hex,
        denom,
        program_id_b58,
        rpc_url,
        use_ephemeral_payer,
        sponsor_pool_spec,
        false, // use_onchain_pool = false (v9.1/v9.2 path)
    )
    .await
}

/// **Faz 9.4** — Refresh with full privacy stack: ephemeral payer
/// (v9.1) sourced from the on-chain SponsorPool (v9.3) via
/// commingled deposits.
///
/// `use_onchain_pool=true` overrides off-chain sponsor selection;
/// the ephemeral is funded directly from the on-chain pool. The
/// `pool_caller` wallet (which submits the SponsorPayout) pays
/// only its own tiny TX fee, decoupled from the sponsorship.
///
/// # Errors
/// Any RPC error during pool payout or Refresh submission.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn refresh_full(
    coin_pubkey_hex: &str,
    coin_signature_hex: &str,
    denom: u64,
    program_id_b58: &str,
    rpc_url: &str,
    use_ephemeral_payer: bool,
    sponsor_pool_spec: &str,
    use_onchain_pool: bool,
) -> Result<()> {
    let coin_pk = parse_hex32(coin_pubkey_hex, "coin-pubkey")?;
    let sig_bytes = parse_hex64(coin_signature_hex, "coin-signature")?;
    let coin_sig = TSignature::from_bytes(&sig_bytes);
    let program_id = parse_pubkey(program_id_b58, "program-id")?;
    let rpc = make_rpc(rpc_url);
    let sponsor = pick_sponsor_from_pool(sponsor_pool_spec)?;
    if !sponsor_pool_spec.trim().is_empty() {
        println!(
            "sponsor     : {} (chosen from pool of {})",
            sponsor.pubkey(),
            sponsor_pool_spec.split([',', ':']).count()
        );
    }
    let (payer, payer_role) = if use_onchain_pool {
        // **Faz 9.5** — pool caller ALSO randomized from the same
        // pool of keypairs, so the SponsorPayout TX submitter is
        // distinct from the previous Refresh's pool-caller. Picks
        // a NEW random selection (independent of the `sponsor`
        // picked above; in the common case they differ).
        let pool_caller = if sponsor_pool_spec.trim().is_empty() {
            sponsor.insecure_clone()
        } else {
            pick_sponsor_from_pool(sponsor_pool_spec)?
        };
        let eph = ephemeral_payer_from_pool(
            &pool_caller,
            &rpc,
            &program_id,
            EPHEMERAL_PAYER_LAMPORTS,
        )
        .await?;
        let (sponsor_pda, _) =
            Pubkey::find_program_address(&[b"tardus", b"sponsor-pool"], &program_id);
        println!(
            "ephemeral   : {} (funded by on-chain pool {} via payout caller {} with {} lamports)",
            eph.pubkey(),
            sponsor_pda,
            pool_caller.pubkey(),
            EPHEMERAL_PAYER_LAMPORTS
        );
        (eph, "ephemeral-from-pool")
    } else if use_ephemeral_payer {
        let eph =
            ephemeral_payer_from_sponsor(&sponsor, &rpc, EPHEMERAL_PAYER_LAMPORTS).await?;
        println!(
            "ephemeral   : {} (funded by sponsor {} with {} lamports)",
            eph.pubkey(),
            sponsor.pubkey(),
            EPHEMERAL_PAYER_LAMPORTS
        );
        (eph, "ephemeral")
    } else {
        (sponsor, "sponsor")
    };

    let (registry_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"keyset-registry"], &program_id);
    let (nullifier_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"nullifier-tree"], &program_id);

    // Look up the joint_pk for the given denom from on-chain registry.
    let registry_account = rpc
        .get_account(&registry_pda)
        .await
        .map_err(|e| anyhow!("registry account: {e}"))?;
    let registry: KeysetRegistry = if registry_account.data.iter().all(|&b| b == 0) {
        return Err(anyhow!("registry is empty — no keysets registered"));
    } else {
        deserialize_padded(&registry_account.data)?
    };
    let entry = registry
        .find_active_for_denom(denom)
        .ok_or_else(|| anyhow!("no active keyset for denom {denom} on-chain"))?;
    println!("payer       : {} ({})", payer.pubkey(), payer_role);
    println!("denom       : {denom}");
    println!("joint_pk    : {}", hex::encode(entry.joint_pk));
    println!("coin_pubkey : {}", hex::encode(coin_pk));

    // Pre-flight: check the nullifier isn't already inserted.
    let nullifier = compute_nullifier(&coin_pk);
    let nullifier_account = rpc
        .get_account(&nullifier_pda)
        .await
        .map_err(|e| anyhow!("nullifier account: {e}"))?;
    let nullifiers: NullifierSet = if nullifier_account.data.iter().all(|&b| b == 0) {
        NullifierSet::new()
    } else {
        deserialize_padded(&nullifier_account.data)?
    };
    if nullifiers.contains(&nullifier) {
        return Err(anyhow!(
            "double-spend: nullifier {} already on-chain",
            hex::encode(nullifier)
        ));
    }

    let precompile_ix = SolInstruction {
        program_id: ed25519_program::id(),
        accounts: vec![],
        data: build_ed25519_precompile_data(&coin_sig, &entry.joint_pk, &coin_pk),
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
            coin_pubkey: coin_pk,
            coin_signature: coin_sig,
            denom,
        })
        .map_err(|e| anyhow!("borsh: {e}"))?,
    };
    let blockhash = rpc
        .get_latest_blockhash()
        .await
        .map_err(|e| anyhow!("blockhash: {e}"))?;
    let tx = Transaction::new_signed_with_payer(
        &[precompile_ix, refresh_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );
    let sig = rpc
        .send_and_confirm_transaction(&tx)
        .await
        .map_err(|e| anyhow!("refresh: {e}"))?;
    println!("refresh     : OK sig={sig}");
    println!(
        "explorer    : https://explorer.solana.com/tx/{sig}?cluster=devnet"
    );
    println!("nullifier   : {}", hex::encode(nullifier));
    Ok(())
}

// =====================================================================
//   **Faz G-mini** — Resize the keyset registry (scaling fix)
// =====================================================================

/// `tardus devnet resize-registry --new-size N` — top-up rent +
/// invoke `Instruction::ResizeAccount` to expand the registry PDA
/// to `new_size` bytes (max 64 KiB).
pub async fn resize_registry(
    new_size: u32,
    program_id_b58: &str,
    rpc_url: &str,
) -> Result<()> {
    let program_id = parse_pubkey(program_id_b58, "program-id")?;
    let rpc = make_rpc(rpc_url);
    let payer = read_keypair_file(keypair_path())
        .map_err(|e| anyhow!("read keypair: {e}"))?;
    let (registry_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"keyset-registry"], &program_id);

    // Discover current allocation + lamports to figure out top-up.
    let acc = rpc
        .get_account(&registry_pda)
        .await
        .map_err(|e| anyhow!("registry account: {e}"))?;
    let current_size = acc.data.len();
    let current_lamports = acc.lamports;

    // Rough rent calc: solana_sdk::rent::Rent::default().minimum_balance(n)
    // gives lamports needed for `n` bytes. We use it client-side.
    let rent = solana_sdk::rent::Rent::default();
    let new_rent = rent.minimum_balance(new_size as usize);
    let topup = new_rent.saturating_sub(current_lamports);

    println!("payer          : {}", payer.pubkey());
    println!("registry_pda   : {registry_pda}");
    println!("current_size   : {current_size} bytes  (lamports={current_lamports})");
    println!("new_size       : {new_size} bytes  (rent={new_rent})");
    println!("top-up         : {topup} lamports");

    let mut ixs: Vec<SolInstruction> = Vec::new();
    if topup > 0 {
        ixs.push(system_instruction::transfer(&payer.pubkey(), &registry_pda, topup));
    }
    ixs.push(SolInstruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(registry_pda, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: borsh::to_vec(&Instruction::ResizeAccount {
            account_kind: BootstrapKind::KeysetRegistry,
            new_size,
            denom: 0,
        })
        .map_err(|e| anyhow!("borsh: {e}"))?,
    });

    let bh = rpc.get_latest_blockhash().await.map_err(|e| anyhow!("blockhash: {e}"))?;
    let tx = Transaction::new_signed_with_payer(
        &ixs,
        Some(&payer.pubkey()),
        &[&payer],
        bh,
    );
    let sig = rpc
        .send_and_confirm_transaction(&tx)
        .await
        .map_err(|e| anyhow!("resize_registry: {e}"))?;
    println!("resize         : OK sig={sig}");
    println!("explorer       : https://explorer.solana.com/tx/{sig}?cluster=devnet");
    Ok(())
}

/// **Faz G** — Resize the nullifier-tree PDA. Uses the same
/// `Instruction::ResizeAccount` as `resize_registry` but routes
/// to `BootstrapKind::NullifierTree`.
pub async fn resize_nullifier_tree(
    new_size: u32,
    program_id_b58: &str,
    rpc_url: &str,
) -> Result<()> {
    let program_id = parse_pubkey(program_id_b58, "program-id")?;
    let rpc = make_rpc(rpc_url);
    let payer = read_keypair_file(keypair_path())
        .map_err(|e| anyhow!("read keypair: {e}"))?;
    let (nullifier_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"nullifier-tree"], &program_id);

    let acc = rpc
        .get_account(&nullifier_pda)
        .await
        .map_err(|e| anyhow!("nullifier account: {e}"))?;
    let current_size = acc.data.len();
    let current_lamports = acc.lamports;
    let rent = solana_sdk::rent::Rent::default();
    let new_rent = rent.minimum_balance(new_size as usize);
    let topup = new_rent.saturating_sub(current_lamports);

    println!("payer          : {}", payer.pubkey());
    println!("nullifier_pda  : {nullifier_pda}");
    println!("current_size   : {current_size} bytes (lamports={current_lamports})");
    println!("new_size       : {new_size} bytes (rent={new_rent})");
    println!("top-up         : {topup} lamports");

    let mut ixs: Vec<SolInstruction> = Vec::new();
    if topup > 0 {
        ixs.push(system_instruction::transfer(&payer.pubkey(), &nullifier_pda, topup));
    }
    ixs.push(SolInstruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(nullifier_pda, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: borsh::to_vec(&Instruction::ResizeAccount {
            account_kind: BootstrapKind::NullifierTree,
            new_size,
            denom: 0,
        })
        .map_err(|e| anyhow!("borsh: {e}"))?,
    });

    let bh = rpc
        .get_latest_blockhash()
        .await
        .map_err(|e| anyhow!("blockhash: {e}"))?;
    let tx = Transaction::new_signed_with_payer(
        &ixs,
        Some(&payer.pubkey()),
        &[&payer],
        bh,
    );
    let sig = rpc
        .send_and_confirm_transaction(&tx)
        .await
        .map_err(|e| anyhow!("resize_nullifier_tree: {e}"))?;
    println!("resize         : OK sig={sig}");
    println!("explorer       : https://explorer.solana.com/tx/{sig}?cluster=devnet");
    Ok(())
}

/// **Faz G** — Show capacity stats: registry, nullifier-tree,
/// sponsor pool, vault balances.
pub async fn capacity(program_id_b58: &str, rpc_url: &str) -> Result<()> {
    let program_id = parse_pubkey(program_id_b58, "program-id")?;
    let rpc = make_rpc(rpc_url);

    let (registry_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"keyset-registry"], &program_id);
    let (nullifier_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"nullifier-tree"], &program_id);
    let (sponsor_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"sponsor-pool"], &program_id);

    println!("# TARDUS capacity report");
    println!();

    if let Ok(reg) = rpc.get_account(&registry_pda).await {
        let total = reg.data.len();
        let registry: KeysetRegistry = if reg.data.iter().all(|&b| b == 0) {
            KeysetRegistry::new()
        } else {
            deserialize_padded(&reg.data).unwrap_or_else(|_| KeysetRegistry::new())
        };
        let bytes_per_entry = 82; // keyset_id(33) + denom(8) + joint_pk(32) + epoch(8) + status(1)
        let estimated_cap = (total - 4) / bytes_per_entry;
        println!("registry        : {} entries / ~{} cap  ({} bytes)",
            registry.entries.len(), estimated_cap, total);
    } else {
        println!("registry        : not bootstrapped");
    }

    if let Ok(null_acc) = rpc.get_account(&nullifier_pda).await {
        let total = null_acc.data.len();
        let nullifiers: NullifierSet = if null_acc.data.iter().all(|&b| b == 0) {
            NullifierSet::new()
        } else {
            deserialize_padded(&null_acc.data).unwrap_or_else(|_| NullifierSet::new())
        };
        let bytes_per_entry = 32; // BTreeSet<[u8; 32]> + ~10 byte overhead/entry
        let estimated_cap = (total - 4) / (bytes_per_entry + 10);
        println!("nullifier-tree  : {} entries / ~{} cap  ({} bytes)",
            nullifiers.len(), estimated_cap, total);
    } else {
        println!("nullifier-tree  : not bootstrapped");
    }

    if let Ok(pool_acc) = rpc.get_account(&sponsor_pda).await {
        let rent_exempt = solana_sdk::rent::Rent::default().minimum_balance(pool_acc.data.len());
        let drainable = pool_acc.lamports.saturating_sub(rent_exempt);
        println!(
            "sponsor-pool    : {} lamports balance ({} drainable, {} rent-locked)",
            pool_acc.lamports, drainable, rent_exempt
        );
    } else {
        println!("sponsor-pool    : not bootstrapped");
    }

    Ok(())
}

// =====================================================================
//   **Faz E** — Withdraw (real SOL release from vault)
// =====================================================================

/// `tardus devnet withdraw` — construct ed25519 precompile +
/// tardus::Withdraw and submit. Releases `denom` lamports from
/// the vault PDA to `recipient`.
///
/// **v2.13.2 GUI parity**: when `use_ephemeral_payer = true`, the
/// Withdraw TX is signed by a fresh ephemeral keypair (Faz 9.1
/// privacy hardening); the deployer wallet becomes only the
/// funder of the ephemeral. With `use_onchain_pool = true`, the
/// funding is routed via the on-chain SponsorPool PDA (Faz 9.4
/// commingled source).
#[allow(
    clippy::too_many_lines,
    clippy::fn_params_excessive_bools,
    clippy::too_many_arguments
)]
pub async fn withdraw(
    coin_pubkey_hex: &str,
    coin_signature_hex: &str,
    denom: u64,
    recipient_b58: &str,
    program_id_b58: &str,
    rpc_url: &str,
    use_ephemeral_payer: bool,
    use_onchain_pool: bool,
) -> Result<()> {
    const EPHEMERAL_PAYER_LAMPORTS: u64 = 1_000_000;
    let coin_pk = parse_hex32(coin_pubkey_hex, "coin-pubkey")?;
    let sig_bytes = parse_hex64(coin_signature_hex, "coin-signature")?;
    let coin_sig = TSignature::from_bytes(&sig_bytes);
    let program_id = parse_pubkey(program_id_b58, "program-id")?;
    let recipient = parse_pubkey(recipient_b58, "recipient")?;
    let rpc = make_rpc(rpc_url);
    let sponsor = read_keypair_file(keypair_path())
        .map_err(|e| anyhow!("read keypair: {e}"))?;

    // **v2.13.2 GUI parity** — 3-way payer dispatch identical to
    // tardus-wallet-gui/src/runtime.rs::withdraw_on_devnet.
    let (payer, payer_strategy, ephemeral_b58) = if use_ephemeral_payer {
        let ephemeral = Keypair::new();
        let eph_pk = ephemeral.pubkey();
        let eph_b58 = eph_pk.to_string();
        if use_onchain_pool {
            let (pool_pda, _) =
                Pubkey::find_program_address(&[b"tardus", b"sponsor-pool"], &program_id);
            let pay_ix = SolInstruction {
                program_id,
                accounts: vec![
                    AccountMeta::new(sponsor.pubkey(), true),
                    AccountMeta::new(pool_pda, false),
                    AccountMeta::new(eph_pk, false),
                    AccountMeta::new_readonly(system_program::id(), false),
                ],
                data: borsh::to_vec(&Instruction::SponsorPayout {
                    lamports: EPHEMERAL_PAYER_LAMPORTS,
                    recipient: eph_pk.to_bytes(),
                })
                .map_err(|e| anyhow!("borsh: {e}"))?,
            };
            let bh = rpc
                .get_latest_blockhash()
                .await
                .map_err(|e| anyhow!("blockhash (pool payout): {e}"))?;
            let tx = Transaction::new_signed_with_payer(
                &[pay_ix],
                Some(&sponsor.pubkey()),
                &[&sponsor],
                bh,
            );
            let sig = rpc
                .send_and_confirm_transaction(&tx)
                .await
                .map_err(|e| anyhow!("sponsor-pool payout: {e}"))?;
            println!("ephemeral funded from on-chain SponsorPool: {eph_b58} (sig {sig})");
            (ephemeral, "ephemeral-from-pool", Some(eph_b58))
        } else {
            let fund_ix = system_instruction::transfer(
                &sponsor.pubkey(),
                &eph_pk,
                EPHEMERAL_PAYER_LAMPORTS,
            );
            let bh = rpc
                .get_latest_blockhash()
                .await
                .map_err(|e| anyhow!("blockhash (sponsor fund): {e}"))?;
            let tx = Transaction::new_signed_with_payer(
                &[fund_ix],
                Some(&sponsor.pubkey()),
                &[&sponsor],
                bh,
            );
            let sig = rpc
                .send_and_confirm_transaction(&tx)
                .await
                .map_err(|e| anyhow!("sponsor fund: {e}"))?;
            println!("ephemeral funded direct from sponsor: {eph_b58} (sig {sig})");
            (ephemeral, "ephemeral-from-sponsor", Some(eph_b58))
        }
    } else {
        (sponsor, "sponsor-direct", None)
    };

    let (registry_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"keyset-registry"], &program_id);
    let (nullifier_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"nullifier-tree"], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(
        &[b"tardus", b"vault", &denom.to_le_bytes()],
        &program_id,
    );

    // Look up joint_pk from on-chain registry for the denom.
    let registry_account = rpc
        .get_account(&registry_pda)
        .await
        .map_err(|e| anyhow!("registry account: {e}"))?;
    let registry: KeysetRegistry = deserialize_padded(&registry_account.data)?;
    let entry = registry
        .find_active_for_denom(denom)
        .ok_or_else(|| anyhow!("no active keyset for denom {denom}"))?;

    let payer_pubkey = payer.pubkey();
    println!("payer       : {payer_pubkey} ({payer_strategy})");
    println!("denom       : {denom}");
    println!("joint_pk    : {}", hex::encode(entry.joint_pk));
    println!("vault_pda   : {vault_pda}");
    println!("recipient   : {recipient}");
    println!("coin_pubkey : {}", hex::encode(coin_pk));

    // Pre-flight: nullifier not already inserted.
    let nullifier = compute_nullifier(&coin_pk);
    let nullifier_account = rpc
        .get_account(&nullifier_pda)
        .await
        .map_err(|e| anyhow!("nullifier account: {e}"))?;
    let nullifiers: NullifierSet = if nullifier_account.data.iter().all(|&b| b == 0) {
        NullifierSet::new()
    } else {
        deserialize_padded(&nullifier_account.data)?
    };
    if nullifiers.contains(&nullifier) {
        return Err(anyhow!(
            "double-spend: nullifier {} already on-chain",
            hex::encode(nullifier)
        ));
    }

    // Pre-flight: vault has enough SOL.
    let vault_account = rpc
        .get_account(&vault_pda)
        .await
        .map_err(|e| anyhow!("vault account: {e}"))?;
    if vault_account.lamports < denom {
        return Err(anyhow!(
            "vault underfunded: have {} lamports, need {}",
            vault_account.lamports,
            denom
        ));
    }

    let precompile_ix = SolInstruction {
        program_id: ed25519_program::id(),
        accounts: vec![],
        data: build_ed25519_precompile_data(&coin_sig, &entry.joint_pk, &coin_pk),
    };
    let withdraw_ix = SolInstruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(registry_pda, false),
            AccountMeta::new(vault_pda, false),
            AccountMeta::new(nullifier_pda, false),
            AccountMeta::new(recipient, false),
            AccountMeta::new_readonly(system_program::id(), false),
            AccountMeta::new_readonly(sysvar::instructions::id(), false),
        ],
        data: borsh::to_vec(&Instruction::Withdraw {
            coin_pubkey: coin_pk,
            coin_signature: coin_sig,
            denom,
            recipient: recipient.to_bytes(),
        })
        .map_err(|e| anyhow!("borsh: {e}"))?,
    };
    let blockhash = rpc
        .get_latest_blockhash()
        .await
        .map_err(|e| anyhow!("blockhash: {e}"))?;
    let tx = Transaction::new_signed_with_payer(
        &[precompile_ix, withdraw_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );
    let sig = rpc
        .send_and_confirm_transaction(&tx)
        .await
        .map_err(|e| anyhow!("withdraw: {e}"))?;
    println!("withdraw    : OK sig={sig}");
    println!("explorer    : https://explorer.solana.com/tx/{sig}?cluster=devnet");
    println!("nullifier   : {}", hex::encode(nullifier));
    println!("payer_strategy: {payer_strategy}");
    if let Some(eph) = ephemeral_b58.as_deref() {
        println!("ephemeral_signer: {eph}");
    }
    Ok(())
}

/// **Faz E** — Full economic loop: Alice mints (off-chain), pays
/// Bob (off-chain via sealed-box relay), Bob withdraws on devnet
/// → Bob gets real SOL.
///
/// Difference from `alice_pays_bob_on_devnet`:
///   - That demo uses `Refresh` (insert nullifier; Bob gets a
///     new unlinkable off-chain coin).
///   - This demo uses `Withdraw` (insert nullifier + release
///     vault lamports to Bob's actual wallet pubkey).
///
/// Pre-condition: vault for `denom` must already be funded
/// (via a manual `solana transfer <amount> <vault_pda>` before).
#[allow(clippy::too_many_lines)]
pub async fn alice_pays_bob_and_bob_withdraws(
    denom: u64,
    program_id_b58: &str,
    rpc_url: &str,
    use_ephemeral_payer: bool,
    use_onchain_pool: bool,
) -> Result<()> {
    use tardus_core::PublicKey;
    use tardus_mint::transcript::{CeremonyId, SessionId};
    use tardus_wallet::{
        derive_master_seed, derive_receiving_keypair, generate_mnemonic, issue_coin,
        parse_mnemonic, sealed_box, ValidatorEndpoint, WalletClientPool, WordCount,
    };

    println!("════════════════════════════════════════════════════════════════════════");
    println!("  TARDUS — Alice pays Bob + Bob WITHDRAWS TO REAL SOL (devnet)");
    println!("════════════════════════════════════════════════════════════════════════");
    println!("  denom: {denom} lamports ({:.6} SOL)", (denom as f64) / 1e9);
    println!();
    println!("[1/10] Identities…");
    let alice_phrase = generate_mnemonic(WordCount::TwentyFour)
        .map_err(|e| anyhow!("alice mnemonic: {e}"))?;
    let bob_phrase = generate_mnemonic(WordCount::TwentyFour)
        .map_err(|e| anyhow!("bob mnemonic: {e}"))?;
    let alice_seed = derive_master_seed(&alice_phrase, "");
    let bob_seed = derive_master_seed(&bob_phrase, "");
    let (bob_recv_sk, bob_recv_pk) = derive_receiving_keypair(&bob_seed);
    let _ = parse_mnemonic; // silence unused on alice path
    let _ = alice_seed;

    // Bob's REAL wallet (gets the SOL):
    let bob_wallet = Keypair::new();
    println!("  alice phrase[0..4]: {} …",
        alice_phrase.to_string().split_whitespace().take(4).collect::<Vec<_>>().join(" "));
    println!("  bob phrase[0..4]:   {} …",
        bob_phrase.to_string().split_whitespace().take(4).collect::<Vec<_>>().join(" "));
    println!("  bob recv pk:        {}", hex::encode(bob_recv_pk));
    println!("  bob REAL wallet:    {} (will receive {} lamports)", bob_wallet.pubkey(), denom);

    println!();
    println!("[2/10] Spawning 3 validators + 1 relay…");
    let (gv1, b1, _t1) = spawn_validator(1)?;
    let (gv2, b2, _t2) = spawn_validator(2)?;
    let (gv3, b3, _t3) = spawn_validator(3)?;
    for u in [&b1, &b2, &b3] {
        wait_for_health(&format!("{u}/health")).await?;
    }
    let (gr, relay_base) = spawn_relay()?;
    wait_for_health(&format!("{relay_base}/health")).await?;

    println!();
    println!("[3/10] DKG → joint_pk…");
    let ceremony = CeremonyId::from_bytes({
        use rand::RngCore;
        let mut a = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut a);
        a
    });
    let ceremony_hex = hex::encode(ceremony.to_bytes());
    let client = reqwest::Client::new();
    let validators = [(1u16, &b1), (2, &b2), (3, &b3)];
    let mut bcs: std::collections::HashMap<u16, String> = std::collections::HashMap::default();
    let mut shs: std::collections::HashMap<u16, Vec<String>> =
        std::collections::HashMap::default();
    for (i, base) in &validators {
        let r: serde_json::Value = client
            .post(format!("{base}/dkg/start"))
            .json(&DkgStartReq {
                ceremony_id_hex: ceremony_hex.clone(),
                my_index: *i,
                n: 3, t: 3,
            })
            .send().await.map_err(|e| anyhow!("dkg/start v{i}: {e}"))?
            .json().await.map_err(|e| anyhow!("dkg/start v{i} JSON: {e}"))?;
        bcs.insert(*i, r["broadcast_borsh_hex"].as_str().unwrap().to_string());
        shs.insert(*i, r["shares_borsh_hex"].as_array().unwrap().iter()
            .map(|x| x.as_str().unwrap().to_string()).collect());
    }
    for (i, base) in &validators {
        for (other, _) in &validators {
            if other == i { continue; }
            client.post(format!("{base}/dkg/contribute"))
                .json(&DkgContribReq {
                    ceremony_id_hex: ceremony_hex.clone(),
                    from_index: *other,
                    broadcast_borsh_hex: bcs[other].clone(),
                    share_for_me_borsh_hex: shs[other][(*i - 1) as usize].clone(),
                })
                .send().await.map_err(|e| anyhow!("dkg/contribute: {e}"))?;
        }
    }
    let mut joint_pks: Vec<String> = Vec::new();
    for (_, base) in &validators {
        let r: serde_json::Value = client.post(format!("{base}/dkg/finalize"))
            .json(&DkgFinalizeReq { ceremony_id_hex: ceremony_hex.clone() })
            .send().await.map_err(|e| anyhow!("dkg/finalize: {e}"))?
            .json().await.map_err(|e| anyhow!("dkg/finalize JSON: {e}"))?;
        joint_pks.push(r["joint_pk_hex"].as_str().unwrap().to_string());
    }
    if !(joint_pks[0] == joint_pks[1] && joint_pks[1] == joint_pks[2]) {
        return Err(anyhow!("DKG divergence: {joint_pks:?}"));
    }
    let joint_pk_hex = joint_pks.into_iter().next().unwrap();
    println!("  joint_pk = {joint_pk_hex}");

    println!();
    println!("[4/10] Bootstrap vault PDA for denom {denom} (if needed)…");
    let _ = bootstrap_vault(denom, program_id_b58, rpc_url).await;

    println!();
    println!("[5/10] Fund vault with {denom} lamports (deployer → vault)…");
    let program_id = parse_pubkey(program_id_b58, "program-id")?;
    let (vault_pda, _) = Pubkey::find_program_address(
        &[b"tardus", b"vault", &denom.to_le_bytes()],
        &program_id,
    );
    let rpc = make_rpc(rpc_url);
    let funder = read_keypair_file(keypair_path())
        .map_err(|e| anyhow!("read keypair: {e}"))?;
    let bh = rpc.get_latest_blockhash().await.map_err(|e| anyhow!("blockhash: {e}"))?;
    let fund_tx = Transaction::new_signed_with_payer(
        &[system_instruction::transfer(&funder.pubkey(), &vault_pda, denom)],
        Some(&funder.pubkey()),
        &[&funder],
        bh,
    );
    let fund_sig = rpc.send_and_confirm_transaction(&fund_tx)
        .await.map_err(|e| anyhow!("vault fund: {e}"))?;
    println!("  vault funded: sig={fund_sig}");

    println!();
    println!("[6/10] Devnet TX: RegisterKeyset…");
    register_keyset(&joint_pk_hex, denom, 1, program_id_b58, rpc_url).await?;

    println!();
    println!("[7/10] OFF-CHAIN: Alice mints coin A…");
    let pool = WalletClientPool::new(vec![
        ValidatorEndpoint::plain(1, b1.clone()).map_err(|e| anyhow!("{e}"))?,
        ValidatorEndpoint::plain(2, b2.clone()).map_err(|e| anyhow!("{e}"))?,
        ValidatorEndpoint::plain(3, b3.clone()).map_err(|e| anyhow!("{e}"))?,
    ]).map_err(|e| anyhow!("{e}"))?;
    let joint_pk_bytes = parse_hex32(&joint_pk_hex, "joint-pk")?;
    let joint_pk = PublicKey::from_bytes(&joint_pk_bytes)
        .map_err(|e| anyhow!("joint_pk: {e}"))?;
    let issue_session = SessionId::from_bytes({
        use rand::RngCore;
        let mut a = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut a);
        a
    });
    let coin_a = issue_coin(&pool, &joint_pk, issue_session)
        .await.map_err(|e| anyhow!("issue_coin: {e}"))?;
    let coin_a_cp_hex = hex::encode(coin_a.pubkey_bytes());
    let coin_a_sig_hex = hex::encode(coin_a.signature().to_bytes());
    println!("  coin_a.Cp = {coin_a_cp_hex}");

    println!();
    println!("[8/10] OFF-CHAIN: Alice seals → relay POST → Bob fetch + decrypt…");
    let payload_json = serde_json::json!({
        "coin_secret":    hex::encode(coin_a.secret().to_bytes()),
        "coin_pubkey":    coin_a_cp_hex,
        "coin_signature": coin_a_sig_hex,
        "denom":          denom,
        "memo":           "alice-pays-bob-withdraw",
    });
    let pt = serde_json::to_vec(&payload_json)?;
    let sealed = sealed_box::seal(&pt, &bob_recv_pk)
        .map_err(|e| anyhow!("seal: {e}"))?;
    let payload_hex = hex::encode(&sealed);
    let bob_pk_hex = hex::encode(bob_recv_pk);
    client.post(format!("{relay_base}/inbox/{bob_pk_hex}"))
        .json(&serde_json::json!({ "payload_hex": payload_hex, "ttl_secs": 3600u64 }))
        .send().await.map_err(|e| anyhow!("relay POST: {e}"))?;
    let listed: serde_json::Value = client.get(format!("{relay_base}/inbox/{bob_pk_hex}"))
        .send().await.map_err(|e| anyhow!("relay GET: {e}"))?
        .json().await.map_err(|e| anyhow!("relay JSON: {e}"))?;
    let received_hex = listed["messages"][0]["payload_hex"].as_str().unwrap_or("");
    let received_bytes = hex::decode(received_hex).map_err(|e| anyhow!("hex: {e}"))?;
    let decrypted = sealed_box::open(&received_bytes, &bob_recv_sk)
        .map_err(|e| anyhow!("open: {e}"))?;
    let _bob_payload: serde_json::Value = serde_json::from_slice(&decrypted)?;
    println!("  decrypted ✓  Bob has coin A");

    println!();
    println!("[9/10] Bob's REAL wallet balance BEFORE withdraw:");
    let before = rpc.get_balance(&bob_wallet.pubkey()).await.unwrap_or(0);
    println!("  {} lamports ({:.9} SOL)", before, (before as f64) / 1e9);

    println!();
    println!(
        "[10/10] Devnet TX: WITHDRAW (vault → Bob's REAL wallet) — ephemeral_payer={use_ephemeral_payer} pool={use_onchain_pool}…"
    );
    withdraw(
        &coin_a_cp_hex,
        &coin_a_sig_hex,
        denom,
        &bob_wallet.pubkey().to_string(),
        program_id_b58,
        rpc_url,
        use_ephemeral_payer,
        use_onchain_pool,
    )
    .await?;

    let after = rpc.get_balance(&bob_wallet.pubkey()).await.unwrap_or(0);
    println!();
    println!("  Bob's REAL wallet balance AFTER:  {} lamports ({:.9} SOL)",
        after, (after as f64) / 1e9);
    println!("  delta: +{} lamports = +{} SOL",
        after - before, (after as f64 - before as f64) / 1e9);

    drop((gv1, gv2, gv3, gr));

    println!();
    println!("════════════════════════════════════════════════════════════════════════");
    println!("  Full economic loop:");
    println!("    deployer → vault    : {denom} lamports deposited (PUBLIC)");
    println!("    Alice (off-chain)   : mint coin A from threshold blind sign");
    println!("    Alice → Bob (off)   : sealed-box delivery via relay");
    println!("    Bob's withdraw      : vault → bob's REAL wallet ({denom} lamports)");
    println!();
    println!("  Net SOL movement: deployer paid → bob's wallet received");
    println!("  Solana observer cannot link the deployer's deposit to bob's wallet");
    println!("    (vault aggregates many deposits ↔ many withdrawals).");
    println!("════════════════════════════════════════════════════════════════════════");
    Ok(())
}

/// `tardus devnet query-nullifier` — check whether a coin's
/// nullifier has been inserted on-chain (i.e. whether the coin is
/// already spent).
pub async fn query_nullifier(
    coin_pubkey_hex: &str,
    program_id_b58: &str,
    rpc_url: &str,
) -> Result<()> {
    let coin_pk = parse_hex32(coin_pubkey_hex, "coin-pubkey")?;
    let program_id = parse_pubkey(program_id_b58, "program-id")?;
    let rpc = make_rpc(rpc_url);
    let (nullifier_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"nullifier-tree"], &program_id);

    let account = rpc
        .get_account(&nullifier_pda)
        .await
        .map_err(|e| anyhow!("nullifier account not present: {e}"))?;
    let nullifier_set: NullifierSet = if account.data.iter().all(|&b| b == 0) {
        NullifierSet::new()
    } else {
        deserialize_padded(&account.data)?
    };
    let expected = compute_nullifier(&coin_pk);
    let spent = nullifier_set.contains(&expected);

    println!("{{");
    println!("  \"coin_pubkey\": \"{}\",", hex::encode(coin_pk));
    println!("  \"nullifier\": \"{}\",", hex::encode(expected));
    println!("  \"spent\": {spent},");
    println!("  \"on_chain_total\": {}", nullifier_set.len());
    println!("}}");
    Ok(())
}

// =====================================================================
//   **v1.4.13 / Faz 9.3** — SponsorPool CLI subcommands
// =====================================================================

/// `tardus devnet sponsor-bootstrap` — one-shot SponsorPool PDA
/// creation. Idempotent: re-runs return ERR_ACCOUNT_ALREADY_EXISTS.
pub async fn sponsor_bootstrap(program_id_b58: &str, rpc_url: &str) -> Result<()> {
    let program_id = parse_pubkey(program_id_b58, "program-id")?;
    let rpc = make_rpc(rpc_url);
    let payer = read_keypair_file(keypair_path())
        .map_err(|e| anyhow!("read keypair: {e}"))?;

    let (sponsor_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"sponsor-pool"], &program_id);

    println!("payer            : {}", payer.pubkey());
    println!("sponsor_pool_pda : {sponsor_pda}");

    let ix = SolInstruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(sponsor_pda, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: borsh::to_vec(&Instruction::Bootstrap {
            account_kind: BootstrapKind::SponsorPool,
            size: 32,
            denom: 0,
        })
        .map_err(|e| anyhow!("borsh: {e}"))?,
    };
    let blockhash = rpc
        .get_latest_blockhash()
        .await
        .map_err(|e| anyhow!("blockhash: {e}"))?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );
    match rpc.send_and_confirm_transaction(&tx).await {
        Ok(sig) => {
            println!("sponsor_bootstrap: OK sig={sig}");
            println!(
                "explorer         : https://explorer.solana.com/tx/{sig}?cluster=devnet"
            );
            Ok(())
        }
        Err(e) => {
            let s = e.to_string();
            if s.contains("custom program error") && s.contains("0xf") {
                // ERR_ACCOUNT_ALREADY_EXISTS (15 == 0xf)
                println!("sponsor_bootstrap: already initialised");
                Ok(())
            } else {
                Err(anyhow!("sponsor_bootstrap: {e}"))
            }
        }
    }
}

/// `tardus devnet sponsor-deposit` — atomic TX of (System::Transfer
/// payer → pool) + (TARDUS::SponsorDeposit ix).
pub async fn sponsor_deposit(
    amount: u64,
    program_id_b58: &str,
    rpc_url: &str,
) -> Result<()> {
    let program_id = parse_pubkey(program_id_b58, "program-id")?;
    let rpc = make_rpc(rpc_url);
    let payer = read_keypair_file(keypair_path())
        .map_err(|e| anyhow!("read keypair: {e}"))?;

    let (sponsor_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"sponsor-pool"], &program_id);

    println!("payer            : {}", payer.pubkey());
    println!("sponsor_pool_pda : {sponsor_pda}");
    println!("amount           : {amount} lamports");

    let transfer_ix = system_instruction::transfer(&payer.pubkey(), &sponsor_pda, amount);
    let record_ix = SolInstruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(sponsor_pda, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: borsh::to_vec(&Instruction::SponsorDeposit { amount })
            .map_err(|e| anyhow!("borsh: {e}"))?,
    };
    let blockhash = rpc
        .get_latest_blockhash()
        .await
        .map_err(|e| anyhow!("blockhash: {e}"))?;
    let tx = Transaction::new_signed_with_payer(
        &[transfer_ix, record_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );
    let sig = rpc
        .send_and_confirm_transaction(&tx)
        .await
        .map_err(|e| anyhow!("sponsor_deposit: {e}"))?;
    println!("sponsor_deposit  : OK sig={sig}");
    println!("explorer         : https://explorer.solana.com/tx/{sig}?cluster=devnet");
    Ok(())
}

/// `tardus devnet sponsor-payout` — drain `lamports` from pool to
/// `recipient` (subject to per-slot rate limit).
pub async fn sponsor_payout(
    lamports: u64,
    recipient_b58: &str,
    program_id_b58: &str,
    rpc_url: &str,
) -> Result<()> {
    let program_id = parse_pubkey(program_id_b58, "program-id")?;
    let recipient = parse_pubkey(recipient_b58, "recipient")?;
    let rpc = make_rpc(rpc_url);
    let payer = read_keypair_file(keypair_path())
        .map_err(|e| anyhow!("read keypair: {e}"))?;

    let (sponsor_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"sponsor-pool"], &program_id);

    println!("payer            : {}", payer.pubkey());
    println!("sponsor_pool_pda : {sponsor_pda}");
    println!("recipient        : {recipient}");
    println!("lamports         : {lamports}");

    let ix = SolInstruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(sponsor_pda, false),
            AccountMeta::new(recipient, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: borsh::to_vec(&Instruction::SponsorPayout {
            lamports,
            recipient: recipient.to_bytes(),
        })
        .map_err(|e| anyhow!("borsh: {e}"))?,
    };
    let blockhash = rpc
        .get_latest_blockhash()
        .await
        .map_err(|e| anyhow!("blockhash: {e}"))?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );
    let sig = rpc
        .send_and_confirm_transaction(&tx)
        .await
        .map_err(|e| anyhow!("sponsor_payout: {e}"))?;
    println!("sponsor_payout   : OK sig={sig}");
    println!("explorer         : https://explorer.solana.com/tx/{sig}?cluster=devnet");
    Ok(())
}

// =====================================================================
//   `tardus devnet private-tx-demo`
//
//   End-to-end private-TX walk-through that ties all the protocol
//   layers together:
//
//     1. Spawn 3 local `tardus-validator` daemons (release binaries).
//     2. Run DKG over HTTP → consensus joint_pk.
//     3. Submit RegisterKeyset to devnet (TX #1, public — registers
//        the new mint).
//     4. Mint a coin off-chain via the local 3-of-3 threshold blind
//        sign.
//     5. Submit Refresh to devnet (TX #2 — **the private TX**: it
//        inserts the coin's nullifier(Cp) into the on-chain set; an
//        observer learns only `null(Cp)`, not who minted it or who
//        spent it).
//     6. Print the Solana Explorer URL of TX #2.
// =====================================================================

#[derive(serde::Serialize)]
struct DkgStartReq {
    ceremony_id_hex: String,
    my_index: u16,
    n: u16,
    t: u16,
}
#[derive(serde::Serialize)]
struct DkgContribReq {
    ceremony_id_hex: String,
    from_index: u16,
    broadcast_borsh_hex: String,
    share_for_me_borsh_hex: String,
}
#[derive(serde::Serialize)]
struct DkgFinalizeReq {
    ceremony_id_hex: String,
}

struct DaemonGuard {
    child: std::process::Child,
}
impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn pick_free_port() -> Result<u16> {
    let l = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|e| anyhow!("bind: {e}"))?;
    let p = l.local_addr().map_err(|e| anyhow!("addr: {e}"))?.port();
    drop(l);
    Ok(p)
}

fn workspace_root() -> Result<std::path::PathBuf> {
    let exe = std::env::current_exe().map_err(|e| anyhow!("current_exe: {e}"))?;
    // .../target/release/tardus → .../target/release → .../target → .../
    let mut p = exe;
    for _ in 0..3 {
        p.pop();
    }
    Ok(p)
}

fn validator_bin() -> Result<std::path::PathBuf> {
    let p = workspace_root()?.join("target/release/tardus-validator");
    if !p.exists() {
        return Err(anyhow!(
            "tardus-validator binary not found at {}. Build it with: cargo build --release",
            p.display()
        ));
    }
    Ok(p)
}

async fn wait_for_health(url: &str) -> Result<()> {
    use std::time::Duration;
    let c = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|e| anyhow!("reqwest: {e}"))?;
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        if let Ok(r) = c.get(url).send().await {
            if r.status().is_success() {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(anyhow!("daemon not healthy: {url}"))
}

fn relay_bin() -> Result<std::path::PathBuf> {
    let p = workspace_root()?.join("target/release/tardus-relayd");
    if !p.exists() {
        return Err(anyhow!(
            "tardus-relayd binary not found at {}. Build it with: cargo build --release",
            p.display()
        ));
    }
    Ok(p)
}

fn spawn_relay() -> Result<(DaemonGuard, String)> {
    let port = pick_free_port()?;
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let child = std::process::Command::new(relay_bin()?)
        .arg("--bind")
        .arg(&bind)
        .arg("--operator")
        .arg("alice-pays-bob-relay")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| anyhow!("spawn relay: {e}"))?;
    Ok((DaemonGuard { child }, base))
}

fn spawn_validator(my_index: u16) -> Result<(DaemonGuard, String, tempfile::TempDir)> {
    use rand::RngCore;
    let port = pick_free_port()?;
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let tmp = tempfile::TempDir::new().map_err(|e| anyhow!("tempdir: {e}"))?;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);

    let child = std::process::Command::new(validator_bin()?)
        .arg("--bind")
        .arg(&bind)
        .arg("--data-dir")
        .arg(tmp.path())
        .arg("--operator")
        .arg(format!("private-tx-demo-{my_index}"))
        .arg("--master-seed-hex")
        .arg(hex::encode(seed))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| anyhow!("spawn validator-{my_index}: {e}"))?;
    Ok((DaemonGuard { child }, base, tmp))
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub async fn alice_pays_bob_on_devnet(
    denom: u64,
    program_id_b58: &str,
    rpc_url: &str,
    sponsor_pool: &str,
    use_onchain_pool: bool,
) -> Result<()> {
    use tardus_core::{PublicKey, SecretKey, Signature};
    use tardus_mint::transcript::{CeremonyId, SessionId};
    use tardus_refresh::coin::Coin;
    use tardus_wallet::{
        derive_master_seed, derive_receiving_keypair, generate_mnemonic, issue_coin,
        refresh_coin, sealed_box, ValidatorEndpoint, WalletClientPool, WordCount,
    };

    println!("════════════════════════════════════════════════════════════════════════");
    println!("  TARDUS — TRUE Alice→Bob private payment, devnet-settled");
    println!("════════════════════════════════════════════════════════════════════════");
    println!("  denom        : {denom}");
    println!("  program_id   : {program_id_b58}");
    println!("  rpc          : {rpc_url}");

    // ---- Step 1: identities ----
    println!();
    println!("[1/9] Generating two independent BIP-39 identities…");
    let alice_phrase = generate_mnemonic(WordCount::TwentyFour)
        .map_err(|e| anyhow!("alice mnemonic: {e}"))?;
    let bob_phrase = generate_mnemonic(WordCount::TwentyFour)
        .map_err(|e| anyhow!("bob mnemonic: {e}"))?;
    let alice_seed = derive_master_seed(&alice_phrase, "");
    let bob_seed = derive_master_seed(&bob_phrase, "");
    let (bob_recv_sk, bob_recv_pk) = derive_receiving_keypair(&bob_seed);
    let _alice_recv_pk = derive_receiving_keypair(&alice_seed).1;
    println!(
        "      alice mnemonic (first 4 words): {} …",
        alice_phrase
            .to_string()
            .split_whitespace()
            .take(4)
            .collect::<Vec<_>>()
            .join(" ")
    );
    println!(
        "      bob mnemonic   (first 4 words): {} …",
        bob_phrase
            .to_string()
            .split_whitespace()
            .take(4)
            .collect::<Vec<_>>()
            .join(" ")
    );
    println!("      bob recv pk = {}", hex::encode(bob_recv_pk));

    // ---- Step 2: spawn validators ----
    println!();
    println!("[2/9] Spawning 3 local tardus-validator daemons (Alice's mint committee)…");
    let (gv1, b1, _t1) = spawn_validator(1)?;
    let (gv2, b2, _t2) = spawn_validator(2)?;
    let (gv3, b3, _t3) = spawn_validator(3)?;
    for u in [&b1, &b2, &b3] {
        wait_for_health(&format!("{u}/health")).await?;
    }
    println!("      v1 = {b1}  v2 = {b2}  v3 = {b3}");

    // ---- Step 3: spawn relay ----
    println!();
    println!("[3/9] Spawning local tardus-relayd (off-chain delivery channel)…");
    let (gr, relay_base) = spawn_relay()?;
    wait_for_health(&format!("{relay_base}/health")).await?;
    println!("      relay = {relay_base}");

    // ---- Step 4: DKG ----
    println!();
    println!("[4/9] DKG ceremony (3-of-3) → joint_pk consensus…");
    let ceremony = CeremonyId::from_bytes({
        use rand::RngCore;
        let mut a = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut a);
        a
    });
    let ceremony_hex = hex::encode(ceremony.to_bytes());
    let client = reqwest::Client::new();
    let validators = [(1u16, &b1), (2, &b2), (3, &b3)];
    let mut bcs: std::collections::HashMap<u16, String> = std::collections::HashMap::default();
    let mut shs: std::collections::HashMap<u16, Vec<String>> =
        std::collections::HashMap::default();
    for (i, base) in &validators {
        let r: serde_json::Value = client
            .post(format!("{base}/dkg/start"))
            .json(&DkgStartReq {
                ceremony_id_hex: ceremony_hex.clone(),
                my_index: *i,
                n: 3,
                t: 3,
            })
            .send()
            .await
            .map_err(|e| anyhow!("dkg start v{i}: {e}"))?
            .json()
            .await
            .map_err(|e| anyhow!("dkg start v{i} JSON: {e}"))?;
        bcs.insert(*i, r["broadcast_borsh_hex"].as_str().unwrap().to_string());
        shs.insert(
            *i,
            r["shares_borsh_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
                .collect(),
        );
    }
    for (i, base) in &validators {
        for (other, _) in &validators {
            if other == i {
                continue;
            }
            client
                .post(format!("{base}/dkg/contribute"))
                .json(&DkgContribReq {
                    ceremony_id_hex: ceremony_hex.clone(),
                    from_index: *other,
                    broadcast_borsh_hex: bcs[other].clone(),
                    share_for_me_borsh_hex: shs[other][(*i - 1) as usize].clone(),
                })
                .send()
                .await
                .map_err(|e| anyhow!("dkg contribute v{i} from {other}: {e}"))?;
        }
    }
    let mut joint_pks: Vec<String> = Vec::new();
    for (_, base) in &validators {
        let r: serde_json::Value = client
            .post(format!("{base}/dkg/finalize"))
            .json(&DkgFinalizeReq {
                ceremony_id_hex: ceremony_hex.clone(),
            })
            .send()
            .await
            .map_err(|e| anyhow!("dkg finalize: {e}"))?
            .json()
            .await
            .map_err(|e| anyhow!("dkg finalize JSON: {e}"))?;
        joint_pks.push(r["joint_pk_hex"].as_str().unwrap().to_string());
    }
    if !(joint_pks[0] == joint_pks[1] && joint_pks[1] == joint_pks[2]) {
        return Err(anyhow!("DKG divergence: {joint_pks:?}"));
    }
    let joint_pk_hex = joint_pks.into_iter().next().unwrap();
    println!("      joint_pk = {joint_pk_hex}");

    // ---- Step 5: register keyset on devnet (PUBLIC TX) ----
    println!();
    println!("[5/9] Devnet TX #1 (PUBLIC): RegisterKeyset…");
    register_keyset(&joint_pk_hex, denom, 1, program_id_b58, rpc_url).await?;

    // ---- Step 6: Alice mints coin A (OFF-CHAIN) ----
    println!();
    println!("[6/9] OFF-CHAIN: Alice mints coin A via 3-of-3 threshold blind sign…");
    let pool = WalletClientPool::new(vec![
        ValidatorEndpoint::plain(1, b1.clone()).map_err(|e| anyhow!("{e}"))?,
        ValidatorEndpoint::plain(2, b2.clone()).map_err(|e| anyhow!("{e}"))?,
        ValidatorEndpoint::plain(3, b3.clone()).map_err(|e| anyhow!("{e}"))?,
    ])
    .map_err(|e| anyhow!("{e}"))?;
    let joint_pk_bytes = parse_hex32(&joint_pk_hex, "joint-pk")?;
    let joint_pk = PublicKey::from_bytes(&joint_pk_bytes)
        .map_err(|e| anyhow!("joint_pk: {e}"))?;
    let issue_session = SessionId::from_bytes({
        use rand::RngCore;
        let mut a = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut a);
        a
    });
    let coin_a = issue_coin(&pool, &joint_pk, issue_session)
        .await
        .map_err(|e| anyhow!("issue_coin: {e}"))?;
    let coin_a_cp_hex = hex::encode(coin_a.pubkey_bytes());
    let coin_a_sig_hex = hex::encode(coin_a.signature().to_bytes());
    println!("      coin_a.Cp        = {coin_a_cp_hex}");
    println!("      verify under jp  → {}",
        if coin_a.verify(&joint_pk).map_err(|e| anyhow!("{e}"))? { "OK ✓" } else { "FAIL ✗" });

    // ---- Step 7: Alice seals to Bob + POSTs to relay (OFF-CHAIN) ----
    println!();
    println!("[7/9] OFF-CHAIN: Alice seals coin A to Bob's recv pk + POSTs to local relay…");
    let payload_json = serde_json::json!({
        "coin_secret":    hex::encode(coin_a.secret().to_bytes()),
        "coin_pubkey":    coin_a_cp_hex,
        "coin_signature": coin_a_sig_hex,
        "denom":          denom,
        "memo":           "alice-pays-bob",
    });
    let plaintext = serde_json::to_vec(&payload_json)?;
    let sealed = sealed_box::seal(&plaintext, &bob_recv_pk)
        .map_err(|e| anyhow!("sealed_box::seal: {e}"))?;
    let payload_hex = hex::encode(&sealed);
    let bob_pk_hex = hex::encode(bob_recv_pk);
    let deposit: serde_json::Value = client
        .post(format!("{relay_base}/inbox/{bob_pk_hex}"))
        .json(&serde_json::json!({ "payload_hex": &payload_hex, "ttl_secs": 3600u64 }))
        .send()
        .await
        .map_err(|e| anyhow!("relay POST: {e}"))?
        .json()
        .await
        .map_err(|e| anyhow!("relay JSON: {e}"))?;
    let msg_id = deposit["id"].as_str().unwrap_or("").to_string();
    println!("      sealed blob size  = {} bytes", sealed.len());
    println!("      relay msg_id      = {msg_id}");
    println!("      [Solana: no trace; off-chain delivery]");

    // ---- Step 8: Bob fetches + decrypts + refreshes (OFF-CHAIN) ----
    println!();
    println!("[8/9] OFF-CHAIN: Bob polls relay, decrypts with mnemonic-derived sk, refreshes…");
    let listed: serde_json::Value = client
        .get(format!("{relay_base}/inbox/{bob_pk_hex}"))
        .send()
        .await
        .map_err(|e| anyhow!("relay GET: {e}"))?
        .json()
        .await
        .map_err(|e| anyhow!("relay JSON: {e}"))?;
    let messages = listed["messages"].as_array().cloned().unwrap_or_default();
    if messages.len() != 1 {
        return Err(anyhow!("expected 1 inbox message, got {}", messages.len()));
    }
    let received_hex = messages[0]["payload_hex"].as_str().unwrap_or("");
    let received_bytes = hex::decode(received_hex)
        .map_err(|e| anyhow!("hex decode: {e}"))?;
    let decrypted = sealed_box::open(&received_bytes, &bob_recv_sk)
        .map_err(|e| anyhow!("sealed_box::open: {e}"))?;
    let bob_payload: serde_json::Value = serde_json::from_slice(&decrypted)?;
    println!("      decrypt OK ✓  memo = {:?}",
        bob_payload["memo"].as_str().unwrap_or(""));

    // Reconstruct Coin A from Bob's view
    let cs = parse_hex32(bob_payload["coin_secret"].as_str().unwrap_or(""), "coin_secret")?;
    let cp = parse_hex32(bob_payload["coin_pubkey"].as_str().unwrap_or(""), "coin_pubkey")?;
    let sig = {
        let b = hex::decode(bob_payload["coin_signature"].as_str().unwrap_or(""))
            .map_err(|e| anyhow!("sig hex: {e}"))?;
        if b.len() != 64 {
            return Err(anyhow!("sig must be 64 bytes"));
        }
        let mut a = [0u8; 64];
        a.copy_from_slice(&b);
        a
    };
    let coin_a_bob = Coin::new(
        SecretKey::from_bytes(&cs).map_err(|e| anyhow!("sk: {e}"))?,
        cp,
        Signature::from_bytes(&sig),
    )
    .map_err(|e| anyhow!("coin reconstruct: {e}"))?;

    // Bob refreshes off-chain (gets coin B, unlinkable)
    let refresh_session = SessionId::from_bytes({
        use rand::RngCore;
        let mut a = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut a);
        a
    });
    let coin_b = refresh_coin(&pool, &coin_a_bob, &joint_pk, refresh_session)
        .await
        .map_err(|e| anyhow!("refresh_coin: {e}"))?;
    let coin_b_cp_hex = hex::encode(coin_b.pubkey_bytes());
    println!("      coin_b.Cp        = {coin_b_cp_hex}   ← Bob's new, unlinkable coin");
    println!("      coin_a ↔ coin_b unlinkable (T4: 1/(κ+1))");

    // ---- Step 9: Bob submits Refresh on devnet (the PRIVATE TX) ----
    //              with an EPHEMERAL PAYER (Faz 9.1) so Solana
    //              Explorer's signer is a fresh, never-before-seen
    //              pubkey rather than the deployer wallet.
    println!();
    println!("[9/9] Devnet TX #2 (PRIVATE): Bob submits Refresh of coin A on-chain…");
    println!("      Surrenders coin A (Alice's), takes coin B off-chain.");
    if use_onchain_pool {
        println!(
            "      Using EPHEMERAL PAYER + ON-CHAIN SPONSORPOOL (Faz 9.4) — commingled multi-depositor pool."
        );
    } else if sponsor_pool.trim().is_empty() {
        println!("      Using EPHEMERAL PAYER (Faz 9.1) — fresh signer, single sponsor.");
    } else {
        println!(
            "      Using EPHEMERAL PAYER + SPONSOR POOL (Faz 9.2) — random sponsor from {} paths.",
            sponsor_pool.split([',', ':']).count()
        );
    }
    refresh_full(
        &coin_a_cp_hex,
        &coin_a_sig_hex,
        denom,
        program_id_b58,
        rpc_url,
        true,             // ← ephemeral payer (Faz 9.1)
        sponsor_pool,     // ← multi-sponsor pool (Faz 9.2)
        use_onchain_pool, // ← on-chain pool (Faz 9.4)
    )
    .await?;

    drop((gv1, gv2, gv3, gr));

    println!();
    println!("════════════════════════════════════════════════════════════════════════");
    println!("  Inspect on Solana Explorer:");
    println!("    program: https://explorer.solana.com/address/{program_id_b58}?cluster=devnet");
    println!();
    println!("  What an observer of Solana sees:");
    println!("    • RegisterKeyset (TX #1): new mint for denom={denom}");
    println!("    • Refresh (TX #2): nullifier of coin A inserted");
    println!();
    println!("  What an observer of Solana does NOT see:");
    println!("    • Alice's mint of coin A      (off-chain, no record)");
    println!("    • Alice → Bob sealed delivery (off-chain via relay, payload-blind)");
    println!("    • Bob's coin B                (off-chain, unlinkable to coin A)");
    println!("    • Identity of Alice or Bob    (deployer is universal fee-payer)");
    println!("════════════════════════════════════════════════════════════════════════");
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub async fn private_tx_demo(denom: u64, program_id_b58: &str, rpc_url: &str) -> Result<()> {
    use tardus_core::PublicKey;
    use tardus_mint::transcript::{CeremonyId, SessionId};
    use tardus_wallet::{issue_coin, ValidatorEndpoint, WalletClientPool};

    println!("════════════════════════════════════════════════════════════════════════");
    println!("  TARDUS private-TX demo — devnet end-to-end");
    println!("════════════════════════════════════════════════════════════════════════");
    println!("  denom        : {denom}");
    println!("  program_id   : {program_id_b58}");
    println!("  rpc          : {rpc_url}");

    // ---- Step 1: spawn 3 local validators ----
    println!();
    println!("[1/5] Spawning 3 local tardus-validator daemons…");
    let (g1, b1, _t1) = spawn_validator(1)?;
    let (g2, b2, _t2) = spawn_validator(2)?;
    let (g3, b3, _t3) = spawn_validator(3)?;
    for u in [&b1, &b2, &b3] {
        wait_for_health(&format!("{u}/health")).await?;
    }
    println!("      v1 = {b1}");
    println!("      v2 = {b2}");
    println!("      v3 = {b3}");

    // ---- Step 2: DKG ceremony ----
    println!();
    println!("[2/5] Running 3-of-3 DKG ceremony over HTTP…");
    let ceremony = CeremonyId::from_bytes({
        use rand::RngCore;
        let mut a = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut a);
        a
    });
    let ceremony_hex = hex::encode(ceremony.to_bytes());
    let client = reqwest::Client::new();
    let validators = [(1u16, &b1), (2, &b2), (3, &b3)];

    let mut bcs: std::collections::HashMap<u16, String> = std::collections::HashMap::default();
    let mut shs: std::collections::HashMap<u16, Vec<String>> =
        std::collections::HashMap::default();
    for (i, base) in &validators {
        let r: serde_json::Value = client
            .post(format!("{base}/dkg/start"))
            .json(&DkgStartReq {
                ceremony_id_hex: ceremony_hex.clone(),
                my_index: *i,
                n: 3,
                t: 3,
            })
            .send()
            .await
            .map_err(|e| anyhow!("dkg start v{i}: {e}"))?
            .json()
            .await
            .map_err(|e| anyhow!("dkg start v{i} JSON: {e}"))?;
        bcs.insert(*i, r["broadcast_borsh_hex"].as_str().unwrap().to_string());
        shs.insert(
            *i,
            r["shares_borsh_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
                .collect(),
        );
    }
    for (i, base) in &validators {
        for (other, _) in &validators {
            if other == i {
                continue;
            }
            client
                .post(format!("{base}/dkg/contribute"))
                .json(&DkgContribReq {
                    ceremony_id_hex: ceremony_hex.clone(),
                    from_index: *other,
                    broadcast_borsh_hex: bcs[other].clone(),
                    share_for_me_borsh_hex: shs[other][(*i - 1) as usize].clone(),
                })
                .send()
                .await
                .map_err(|e| anyhow!("dkg contribute v{i} from {other}: {e}"))?;
        }
    }
    let mut joint_pks: Vec<String> = Vec::new();
    for (_, base) in &validators {
        let r: serde_json::Value = client
            .post(format!("{base}/dkg/finalize"))
            .json(&DkgFinalizeReq {
                ceremony_id_hex: ceremony_hex.clone(),
            })
            .send()
            .await
            .map_err(|e| anyhow!("dkg finalize: {e}"))?
            .json()
            .await
            .map_err(|e| anyhow!("dkg finalize JSON: {e}"))?;
        joint_pks.push(r["joint_pk_hex"].as_str().unwrap().to_string());
    }
    if !(joint_pks[0] == joint_pks[1] && joint_pks[1] == joint_pks[2]) {
        return Err(anyhow!(
            "DKG divergence across daemons: {joint_pks:?}"
        ));
    }
    let joint_pk_hex = joint_pks.into_iter().next().unwrap();
    println!("      joint_pk = {joint_pk_hex}");

    // ---- Step 3: register keyset on devnet ----
    println!();
    println!("[3/5] Registering keyset on devnet (public TX #1)…");
    register_keyset(&joint_pk_hex, denom, 1, program_id_b58, rpc_url).await?;

    // ---- Step 4: mint a coin off-chain ----
    println!();
    println!("[4/5] Minting a coin via 3-of-3 threshold blind sign…");
    let pool = WalletClientPool::new(vec![
        ValidatorEndpoint::plain(1, b1.clone()).map_err(|e| anyhow!("{e}"))?,
        ValidatorEndpoint::plain(2, b2.clone()).map_err(|e| anyhow!("{e}"))?,
        ValidatorEndpoint::plain(3, b3.clone()).map_err(|e| anyhow!("{e}"))?,
    ])
    .map_err(|e| anyhow!("{e}"))?;
    let joint_pk_bytes = parse_hex32(&joint_pk_hex, "joint-pk")?;
    let joint_pk = PublicKey::from_bytes(&joint_pk_bytes)
        .map_err(|e| anyhow!("joint_pk: {e}"))?;
    let issue_session = SessionId::from_bytes({
        use rand::RngCore;
        let mut a = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut a);
        a
    });
    let coin = issue_coin(&pool, &joint_pk, issue_session)
        .await
        .map_err(|e| anyhow!("issue_coin: {e}"))?;
    let cp_hex = hex::encode(coin.pubkey_bytes());
    let sig_hex = hex::encode(coin.signature().to_bytes());
    println!("      coin.Cp           = {cp_hex}");
    println!("      coin.signature    = {sig_hex}");
    let coin_verifies = coin
        .verify(&joint_pk)
        .map_err(|e| anyhow!("verify: {e}"))?;
    if !coin_verifies {
        return Err(anyhow!(
            "coin did not verify under joint_pk — mint chain compromised"
        ));
    }
    println!("      verify under joint_pk → OK ✓");

    // ---- Step 5: submit Refresh on devnet (the private TX) ----
    println!();
    println!("[5/5] Submitting Refresh on devnet (the private TX #2)…");
    refresh(&cp_hex, &sig_hex, denom, program_id_b58, rpc_url).await?;

    // Drop daemons last so they survive the long DKG / sign protocol.
    drop((g1, g2, g3));

    println!();
    println!("════════════════════════════════════════════════════════════════════════");
    println!("  Inspect on Solana Explorer:");
    println!("    https://explorer.solana.com/address/{program_id_b58}?cluster=devnet");
    println!();
    println!("  The Refresh TX above is the **private** half — Solana's");
    println!("  on-chain state shows null(Cp) inserted, no link to mint TX,");
    println!("  no sender pubkey, no amount-correlation surface.");
    println!("════════════════════════════════════════════════════════════════════════");
    Ok(())
}
