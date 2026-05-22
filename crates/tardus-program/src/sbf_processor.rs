//! Solana-aware instruction handlers (Faz 1.4.2).
//!
//! Each handler loads the relevant accounts, verifies them as
//! canonical PDAs, deserialises any program-owned state, dispatches
//! to the runtime-agnostic processor in [`crate::processor`], and
//! re-serialises the mutated state back into account data.
//!
//! ## Account ordering convention
//!
//! Every instruction places signers first, then the program-owned
//! state accounts in the order they appear in the registry → vault →
//! nullifier-set hierarchy, then external context (recipient, system
//! program) last.
//!
//! ## Lamport movement
//!
//! For SOL deposit/withdraw, the vault is a system-owned PDA holding
//! only lamports (no program data). Withdrawal uses `invoke_signed`
//! to transfer SOL out via the system program with the vault PDA's
//! seeds. Deposit reads the vault's current lamports balance and
//! checks the post-condition; the actual lamport movement comes from
//! a preceding `system_instruction::transfer` in the same transaction
//! (Solana TX atomicity guarantees both succeed or both fail).
//!
//! Token-2022 Confidential Mint integration is deferred to v1.4.3
//! (requires devnet feature-gate verification — see
//! `research/PRODUCTION_LESSONS.md` §R6 and Wirth's Faz 1.4.2 brief).
//! Light Protocol nullifier-tree CPI is deferred to v1.4.3 (Light SDK
//! 1.0 release pending — Yuanchen's note).

// `msg!` from solana-program expands to `format!` calls; we are
// `no_std` with `alloc`, so format must be in scope.
#![allow(
    // `solana_program::system_instruction` deprecation noted;
    // v1.4.3 migrates to `solana_system_interface`.
    deprecated,
    // Pedantic clippy lints irrelevant to security-correct SBF code:
    clippy::redundant_closure,
    clippy::missing_errors_doc,
    clippy::let_unit_value,
    clippy::match_single_binding
)]

use alloc::{format, vec::Vec};
use borsh::BorshDeserialize;
use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    msg,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    system_instruction,
};

use crate::{
    ed25519_verifier::verify_ed25519_precompile,
    instruction::{BootstrapKind, Instruction},
    pda,
    processor,
    state::{KeysetRegistry, KeysetStatus, NullifierSet, SponsorPool},
};
use solana_program::{clock::Clock, rent::Rent, sysvar::Sysvar};

// =====================================================================
// Custom error code mapping
// =====================================================================

const ERR_CORE: u32 = 1;
const ERR_UNKNOWN_KEYSET: u32 = 2;
const ERR_KEYSET_REVOKED: u32 = 3;
const ERR_KEYSET_ALREADY_REGISTERED: u32 = 4;
const ERR_KEYSET_REGISTRY_FULL: u32 = 5;
const ERR_COIN_SIG_INVALID: u32 = 6;
const ERR_COIN_PUBKEY_MISMATCH: u32 = 7;
const ERR_DOUBLE_SPEND: u32 = 8;
const ERR_DEPOSIT_AMOUNT_MISMATCH: u32 = 9;
const ERR_REFRESH_DENOM_MISMATCH: u32 = 10;
const ERR_VAULT_INSUFFICIENT: u32 = 11;
const ERR_VAULT_INVARIANT: u32 = 12;
const ERR_INSUFFICIENT_THRESHOLD: u32 = 13;
const ERR_INSTRUCTION_MALFORMED: u32 = 14;
const ERR_ACCOUNT_ALREADY_EXISTS: u32 = 15;
const ERR_BOOTSTRAP_SIZE_INVALID: u32 = 16;

fn map_error(e: crate::Error) -> ProgramError {
    use crate::Error;
    ProgramError::Custom(match e {
        Error::Core(_) => ERR_CORE,
        Error::UnknownKeysetId => ERR_UNKNOWN_KEYSET,
        Error::KeysetRevoked => ERR_KEYSET_REVOKED,
        Error::KeysetAlreadyRegistered => ERR_KEYSET_ALREADY_REGISTERED,
        Error::KeysetRegistryFull => ERR_KEYSET_REGISTRY_FULL,
        Error::CoinSignatureInvalid => ERR_COIN_SIG_INVALID,
        Error::CoinPubkeyMismatch => ERR_COIN_PUBKEY_MISMATCH,
        Error::DoubleSpend => ERR_DOUBLE_SPEND,
        Error::DepositAmountMismatch => ERR_DEPOSIT_AMOUNT_MISMATCH,
        Error::RefreshDenominationMismatch => ERR_REFRESH_DENOM_MISMATCH,
        Error::VaultInsufficientCollateral => ERR_VAULT_INSUFFICIENT,
        Error::VaultInvariantViolation => ERR_VAULT_INVARIANT,
        Error::InsufficientThresholdAuth => ERR_INSUFFICIENT_THRESHOLD,
        Error::InstructionMalformed => ERR_INSTRUCTION_MALFORMED,
    })
}

// =====================================================================
// PDA helpers
// =====================================================================

fn verify_keyset_registry_pda(account: &AccountInfo, program_id: &Pubkey) -> Result<u8, ProgramError> {
    let seeds_owned = pda::keyset_registry_seeds();
    let seeds: Vec<&[u8]> = seeds_owned.iter().map(Vec::as_slice).collect();
    let (expected, bump) = Pubkey::find_program_address(&seeds, program_id);
    if account.key != &expected {
        msg!("tardus: keyset registry PDA mismatch");
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(bump)
}

fn verify_nullifier_tree_pda(account: &AccountInfo, program_id: &Pubkey) -> Result<u8, ProgramError> {
    let seeds_owned = pda::nullifier_tree_seeds();
    let seeds: Vec<&[u8]> = seeds_owned.iter().map(Vec::as_slice).collect();
    let (expected, bump) = Pubkey::find_program_address(&seeds, program_id);
    if account.key != &expected {
        msg!("tardus: nullifier tree PDA mismatch");
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(bump)
}

fn verify_vault_pda(
    account: &AccountInfo,
    denom: u64,
    program_id: &Pubkey,
) -> Result<u8, ProgramError> {
    let seeds_owned = pda::vault_seeds(denom);
    let seeds: Vec<&[u8]> = seeds_owned.iter().map(Vec::as_slice).collect();
    let (expected, bump) = Pubkey::find_program_address(&seeds, program_id);
    if account.key != &expected {
        msg!("tardus: vault PDA mismatch for denom {}", denom);
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(bump)
}

// =====================================================================
// State load / store
// =====================================================================

fn load_registry(account: &AccountInfo) -> Result<KeysetRegistry, ProgramError> {
    let data = account.data.borrow();
    if data.iter().all(|&b| b == 0) {
        Ok(KeysetRegistry::new())
    } else {
        // Account data is pre-allocated with trailing padding; borsh's
        // strict `try_from_slice` rejects unconsumed bytes. Use the
        // reader interface so we read only what's serialised.
        let mut reader: &[u8] = &data;
        KeysetRegistry::deserialize_reader(&mut reader)
            .map_err(|_| ProgramError::InvalidAccountData)
    }
}

fn store_registry(account: &AccountInfo, registry: &KeysetRegistry) -> ProgramResult {
    let bytes = borsh::to_vec(registry).map_err(|_| ProgramError::InvalidAccountData)?;
    let mut data = account.data.borrow_mut();
    if bytes.len() > data.len() {
        msg!("tardus: registry account too small ({} < {})", data.len(), bytes.len());
        return Err(ProgramError::AccountDataTooSmall);
    }
    data[..bytes.len()].copy_from_slice(&bytes);
    Ok(())
}

fn load_nullifiers(account: &AccountInfo) -> Result<NullifierSet, ProgramError> {
    let data = account.data.borrow();
    if data.iter().all(|&b| b == 0) {
        Ok(NullifierSet::new())
    } else {
        let mut reader: &[u8] = &data;
        NullifierSet::deserialize_reader(&mut reader)
            .map_err(|_| ProgramError::InvalidAccountData)
    }
}

fn store_nullifiers(account: &AccountInfo, nullifiers: &NullifierSet) -> ProgramResult {
    let bytes = borsh::to_vec(nullifiers).map_err(|_| ProgramError::InvalidAccountData)?;
    let mut data = account.data.borrow_mut();
    if bytes.len() > data.len() {
        msg!("tardus: nullifier tree too small");
        return Err(ProgramError::AccountDataTooSmall);
    }
    data[..bytes.len()].copy_from_slice(&bytes);
    Ok(())
}

// =====================================================================
// Handlers
// =====================================================================

/// Accounts: [signer (committee aggregator), keyset_registry (mut PDA)]
pub fn register_keyset(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    ix: &Instruction,
) -> ProgramResult {
    let [signer, registry_account] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !signer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let _bump = verify_keyset_registry_pda(registry_account, program_id)?;

    let mut registry = load_registry(registry_account)?;
    processor::process_register_keyset(&mut registry, ix).map_err(map_error)?;
    store_registry(registry_account, &registry)?;

    msg!("tardus: keyset registered");
    Ok(())
}

/// Accounts: [signer (depositor), keyset_registry (read PDA), vault (mut PDA)]
pub fn deposit(program_id: &Pubkey, accounts: &[AccountInfo], ix: &Instruction) -> ProgramResult {
    let [signer, registry_account, vault_account] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !signer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let _r_bump = verify_keyset_registry_pda(registry_account, program_id)?;

    let Instruction::Deposit { denom, lamports } = ix else {
        return Err(ProgramError::Custom(ERR_INSTRUCTION_MALFORMED));
    };
    let _v_bump = verify_vault_pda(vault_account, *denom, program_id)?;

    let registry = load_registry(registry_account)?;
    // The lamport movement is expected to come from a system_program::transfer
    // earlier in the same transaction; the post-condition check verifies it.
    let observed_lamports = vault_account.lamports();
    if observed_lamports < *lamports {
        msg!(
            "tardus: deposit post-condition: vault has {} lamports, expected ≥ {}",
            observed_lamports,
            lamports
        );
        return Err(ProgramError::InsufficientFunds);
    }
    // The v1 `Vault` struct isn't persisted on-chain in v1.4.2; vault SOL
    // balance IS the source of truth. Validate the registry has an active
    // keyset for the denomination.
    let mut shadow_vault = crate::state::Vault::new(*denom);
    shadow_vault.collateral = observed_lamports;
    processor::process_deposit(&registry, &mut shadow_vault, ix).map_err(map_error)?;

    msg!("tardus: deposit denom={} lamports={}", denom, lamports);
    Ok(())
}

/// Accounts: [signer, keyset_registry (read PDA), nullifier_set (mut PDA),
///            instructions_sysvar]
///
/// **v1.4.4 change:** signature verification is delegated to the
/// Solana `ed25519_program` precompile. The caller MUST submit a
/// preceding precompile instruction in the same TX that verifies
/// `(joint_pk, coin_pubkey, coin_signature)`. See
/// `crate::ed25519_verifier` for the canonical layout.
pub fn refresh(program_id: &Pubkey, accounts: &[AccountInfo], ix: &Instruction) -> ProgramResult {
    let [signer, registry_account, nullifier_account, instructions_sysvar] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !signer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let _r_bump = verify_keyset_registry_pda(registry_account, program_id)?;
    let _n_bump = verify_nullifier_tree_pda(nullifier_account, program_id)?;

    let Instruction::Refresh {
        coin_pubkey,
        coin_signature,
        denom,
    } = ix
    else {
        return Err(ProgramError::Custom(ERR_INSTRUCTION_MALFORMED));
    };

    let registry = load_registry(registry_account)?;
    let entry = registry
        .find_active_for_denom(*denom)
        .ok_or(ProgramError::Custom(ERR_UNKNOWN_KEYSET))?;
    if entry.status != KeysetStatus::Active {
        return Err(ProgramError::Custom(ERR_KEYSET_REVOKED));
    }

    // SBF: verify ed25519 sig via precompile (avoids curve25519-dalek
    // variable-base scalar mul that would exceed the SBF stack budget).
    verify_ed25519_precompile(
        instructions_sysvar,
        &entry.joint_pk,
        coin_pubkey,
        coin_signature,
    )?;

    let nullifier = processor::compute_nullifier(coin_pubkey);
    let mut nullifiers = load_nullifiers(nullifier_account)?;
    if !nullifiers.insert(nullifier) {
        return Err(ProgramError::Custom(ERR_DOUBLE_SPEND));
    }
    store_nullifiers(nullifier_account, &nullifiers)?;

    msg!("tardus: refresh nullifier inserted");
    Ok(())
}

/// Accounts: [signer (coin holder), keyset_registry (read PDA),
///            vault (mut PDA), nullifier_set (mut PDA),
///            recipient (mut), system_program, instructions_sysvar]
///
/// **v1.4.4 change:** signature verification is delegated to the
/// Solana `ed25519_program` precompile via the instructions sysvar.
pub fn withdraw(program_id: &Pubkey, accounts: &[AccountInfo], ix: &Instruction) -> ProgramResult {
    let [signer, registry_account, vault_account, nullifier_account, recipient_account, system_program_account, instructions_sysvar] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !signer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let Instruction::Withdraw {
        coin_pubkey,
        coin_signature,
        denom,
        recipient,
    } = ix
    else {
        return Err(ProgramError::Custom(ERR_INSTRUCTION_MALFORMED));
    };
    if recipient_account.key.to_bytes() != *recipient {
        msg!("tardus: recipient account does not match instruction recipient");
        return Err(ProgramError::InvalidAccountData);
    }
    if !solana_program::system_program::check_id(system_program_account.key) {
        return Err(ProgramError::IncorrectProgramId);
    }

    let _r_bump = verify_keyset_registry_pda(registry_account, program_id)?;
    let v_bump = verify_vault_pda(vault_account, *denom, program_id)?;
    let _n_bump = verify_nullifier_tree_pda(nullifier_account, program_id)?;

    let registry = load_registry(registry_account)?;
    let entry = registry
        .find_active_for_denom(*denom)
        .ok_or(ProgramError::Custom(ERR_UNKNOWN_KEYSET))?;
    if entry.status != KeysetStatus::Active {
        return Err(ProgramError::Custom(ERR_KEYSET_REVOKED));
    }

    // SBF: signature verification via ed25519 precompile.
    verify_ed25519_precompile(
        instructions_sysvar,
        &entry.joint_pk,
        coin_pubkey,
        coin_signature,
    )?;

    let nullifier = processor::compute_nullifier(coin_pubkey);
    let mut nullifiers = load_nullifiers(nullifier_account)?;
    if !nullifiers.insert(nullifier) {
        return Err(ProgramError::Custom(ERR_DOUBLE_SPEND));
    }
    store_nullifiers(nullifier_account, &nullifiers)?;

    let observed_lamports = vault_account.lamports();
    if observed_lamports < *denom {
        return Err(ProgramError::Custom(ERR_VAULT_INSUFFICIENT));
    }

    // Transfer lamports from vault PDA to recipient via system program.
    let transfer_ix =
        system_instruction::transfer(vault_account.key, recipient_account.key, *denom);
    let seeds_owned = pda::vault_seeds(*denom);
    let mut seeds_refs: Vec<&[u8]> = seeds_owned.iter().map(Vec::as_slice).collect();
    let bump_slice = [v_bump];
    seeds_refs.push(&bump_slice);
    invoke_signed(
        &transfer_ix,
        &[
            vault_account.clone(),
            recipient_account.clone(),
            system_program_account.clone(),
        ],
        &[&seeds_refs],
    )?;

    msg!(
        "tardus: withdraw denom={} to recipient (lamports={})",
        denom,
        denom
    );
    Ok(())
}

/// Accounts: [signer (committee aggregator), keyset_registry (mut PDA)]
pub fn revoke(program_id: &Pubkey, accounts: &[AccountInfo], ix: &Instruction) -> ProgramResult {
    let [signer, registry_account] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !signer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let _bump = verify_keyset_registry_pda(registry_account, program_id)?;

    let mut registry = load_registry(registry_account)?;
    processor::process_revoke(&mut registry, ix).map_err(map_error)?;
    store_registry(registry_account, &registry)?;

    msg!("tardus: keyset revoked");
    Ok(())
}

// Cap allocation size at 64 KB to prevent DoS via huge PDA creation.
const BOOTSTRAP_MAX_SIZE: u32 = 64 * 1024;

/// Accounts: [funder (signer), target_pda (mut), system_program]
///
/// Idempotent allocation of a program-owned PDA (or system-owned vault PDA).
/// The funder pays rent-exemption from their own lamports.
pub fn bootstrap(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    ix: &Instruction,
) -> ProgramResult {
    let [funder, target_account, system_program_account] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !funder.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !solana_program::system_program::check_id(system_program_account.key) {
        return Err(ProgramError::IncorrectProgramId);
    }

    let Instruction::Bootstrap {
        account_kind,
        size,
        denom,
    } = ix
    else {
        return Err(ProgramError::Custom(ERR_INSTRUCTION_MALFORMED));
    };

    // Resolve canonical PDA seeds + bump for the requested account kind.
    let (seeds_owned, alloc_size, owner) = match account_kind {
        BootstrapKind::KeysetRegistry => {
            if *size == 0 || *size > BOOTSTRAP_MAX_SIZE {
                return Err(ProgramError::Custom(ERR_BOOTSTRAP_SIZE_INVALID));
            }
            (pda::keyset_registry_seeds(), *size, *program_id)
        }
        BootstrapKind::NullifierTree => {
            if *size == 0 || *size > BOOTSTRAP_MAX_SIZE {
                return Err(ProgramError::Custom(ERR_BOOTSTRAP_SIZE_INVALID));
            }
            (pda::nullifier_tree_seeds(), *size, *program_id)
        }
        BootstrapKind::Vault => {
            // Vault is a system-owned account holding only lamports.
            (
                pda::vault_seeds(*denom),
                0u32,
                solana_program::system_program::id(),
            )
        }
        BootstrapKind::SponsorPool => {
            // **v1.4.13** — SponsorPool is program-owned so we can
            // write `last_payout_slot` state to it; it also holds
            // lamports (the actual sponsor pool funds). Size is
            // fixed at borsh(SponsorPool) = 24 bytes; we round up
            // to 32 for forward compatibility.
            (pda::sponsor_pool_seeds(), 32u32, *program_id)
        }
    };
    let seeds_refs: Vec<&[u8]> = seeds_owned.iter().map(Vec::as_slice).collect();
    let (expected_pda, bump) = Pubkey::find_program_address(&seeds_refs, program_id);
    if target_account.key != &expected_pda {
        msg!("tardus: bootstrap PDA mismatch");
        return Err(ProgramError::InvalidAccountData);
    }
    if target_account.lamports() > 0 {
        msg!("tardus: bootstrap target account already exists");
        return Err(ProgramError::Custom(ERR_ACCOUNT_ALREADY_EXISTS));
    }

    let rent = Rent::get()?;
    let rent_lamports = rent.minimum_balance(alloc_size as usize);

    let create_ix = system_instruction::create_account(
        funder.key,
        target_account.key,
        rent_lamports,
        u64::from(alloc_size),
        &owner,
    );

    let bump_slice = [bump];
    let mut signer_seeds: Vec<&[u8]> = seeds_owned.iter().map(Vec::as_slice).collect();
    signer_seeds.push(&bump_slice);

    invoke_signed(
        &create_ix,
        &[
            funder.clone(),
            target_account.clone(),
            system_program_account.clone(),
        ],
        &[&signer_seeds],
    )?;

    msg!(
        "tardus: bootstrap kind={} size={} denom={}",
        match account_kind {
            BootstrapKind::KeysetRegistry => "registry",
            BootstrapKind::NullifierTree => "nullifier",
            BootstrapKind::Vault => "vault",
            BootstrapKind::SponsorPool => "sponsor-pool",
        },
        alloc_size,
        denom
    );
    Ok(())
}

// =====================================================================
//   **v1.4.13 / Faz 9.3** — SponsorPool handlers
// =====================================================================

fn verify_sponsor_pool_pda(
    account: &AccountInfo,
    program_id: &Pubkey,
) -> Result<u8, ProgramError> {
    let seeds_owned = pda::sponsor_pool_seeds();
    let seeds_refs: Vec<&[u8]> = seeds_owned.iter().map(Vec::as_slice).collect();
    let (expected, bump) = Pubkey::find_program_address(&seeds_refs, program_id);
    if account.key != &expected {
        msg!("tardus: sponsor-pool PDA mismatch");
        return Err(ProgramError::InvalidAccountData);
    }
    if account.owner != program_id {
        msg!("tardus: sponsor-pool PDA wrong owner");
        return Err(ProgramError::IncorrectProgramId);
    }
    Ok(bump)
}

fn load_sponsor_pool(account: &AccountInfo) -> Result<SponsorPool, ProgramError> {
    let data = account.data.borrow();
    if data.iter().all(|&b| b == 0) {
        return Ok(SponsorPool::default());
    }
    SponsorPool::deserialize_reader(&mut &data[..]).map_err(|e| {
        msg!("tardus: sponsor-pool deserialise: {}", format!("{e}"));
        ProgramError::InvalidAccountData
    })
}

fn store_sponsor_pool(account: &AccountInfo, pool: &SponsorPool) -> ProgramResult {
    let mut data = account.data.borrow_mut();
    let bytes = borsh::to_vec(pool).map_err(|_| ProgramError::AccountDataTooSmall)?;
    if bytes.len() > data.len() {
        return Err(ProgramError::AccountDataTooSmall);
    }
    data[..bytes.len()].copy_from_slice(&bytes);
    Ok(())
}

/// **v1.4.14 / Faz G-mini** — Resize a program-owned PDA to a
/// larger byte allocation. Top-up rent transferred from `funder`
/// in the same TX via a paired System::Transfer (caller's
/// responsibility — handler verifies post-balance ≥ new rent).
///
/// Account layout:
///   [0] funder              (signer, writable)
///   [1] target_pda          (writable, program-owned)
///   [2] system_program
#[allow(clippy::too_many_lines)]
pub fn resize_account(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    ix: &Instruction,
) -> ProgramResult {
    let [funder, target_account, system_program_account] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !funder.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !solana_program::system_program::check_id(system_program_account.key) {
        return Err(ProgramError::IncorrectProgramId);
    }
    let Instruction::ResizeAccount {
        account_kind,
        new_size,
        denom,
    } = ix
    else {
        return Err(ProgramError::Custom(ERR_INSTRUCTION_MALFORMED));
    };
    if *new_size == 0 || *new_size > BOOTSTRAP_MAX_SIZE {
        return Err(ProgramError::Custom(ERR_BOOTSTRAP_SIZE_INVALID));
    }

    // Verify the PDA matches the requested kind.
    let seeds_owned = match account_kind {
        BootstrapKind::KeysetRegistry => pda::keyset_registry_seeds(),
        BootstrapKind::NullifierTree => pda::nullifier_tree_seeds(),
        BootstrapKind::SponsorPool => pda::sponsor_pool_seeds(),
        BootstrapKind::Vault => {
            // Vault is system-owned (lamports only); resize meaningless.
            return Err(ProgramError::Custom(ERR_INSTRUCTION_MALFORMED));
        }
    };
    let seeds_refs: Vec<&[u8]> = seeds_owned.iter().map(Vec::as_slice).collect();
    let (expected, _bump) = Pubkey::find_program_address(&seeds_refs, program_id);
    if target_account.key != &expected {
        msg!("tardus: resize PDA mismatch");
        return Err(ProgramError::InvalidAccountData);
    }
    if target_account.owner != program_id {
        msg!("tardus: resize target not program-owned");
        return Err(ProgramError::IncorrectProgramId);
    }

    let current_size = target_account.data_len();
    if (*new_size as usize) <= current_size {
        msg!(
            "tardus: resize new_size {} not larger than current {}",
            new_size,
            current_size
        );
        return Err(ProgramError::Custom(ERR_BOOTSTRAP_SIZE_INVALID));
    }

    // Rent top-up needed.
    let rent = Rent::get()?;
    let new_rent = rent.minimum_balance(*new_size as usize);
    let current_lamports = target_account.lamports();
    if current_lamports < new_rent {
        // Caller must have included a paired System::Transfer for
        // (new_rent - current_lamports) lamports. We verify the
        // post-condition; the actual transfer is in the same TX.
        let needed = new_rent - current_lamports;
        msg!("tardus: resize needs +{} lamports of rent top-up", needed);
        return Err(ProgramError::Custom(ERR_VAULT_INSUFFICIENT));
    }

    // Reallocate. zero-init the new tail bytes (so subsequent
    // deserialize-padded path works correctly).
    target_account.realloc(*new_size as usize, true)?;

    msg!(
        "tardus: resize kind={} {} → {} bytes (denom={})",
        match account_kind {
            BootstrapKind::KeysetRegistry => "registry",
            BootstrapKind::NullifierTree => "nullifier",
            BootstrapKind::SponsorPool => "sponsor-pool",
            BootstrapKind::Vault => "vault",
        },
        current_size,
        new_size,
        denom
    );
    Ok(())
}

/// `SponsorDeposit` — anyone calls this to add SOL to the pool.
/// Account layout:
///   [0] funder      (signer, writable)
///   [1] pool_pda    (writable)
///   [2] system_program
///
/// Lamports flow via a `system_instruction::transfer` that the
/// caller MUST include in the SAME TX (atomic). This handler only
/// updates the `total_deposits` counter.
pub fn sponsor_deposit(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    ix: &Instruction,
) -> ProgramResult {
    let [funder, pool_account, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !funder.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let _bump = verify_sponsor_pool_pda(pool_account, program_id)?;
    let Instruction::SponsorDeposit { amount } = ix else {
        return Err(ProgramError::Custom(ERR_INSTRUCTION_MALFORMED));
    };

    // Update counter. The lamport transfer itself is the caller's
    // separate System::Transfer ix in the same TX.
    let mut pool = load_sponsor_pool(pool_account)?;
    pool.total_deposits = pool.total_deposits.saturating_add(*amount);
    store_sponsor_pool(pool_account, &pool)?;
    msg!("tardus: sponsor-deposit amount={}", amount);
    Ok(())
}

/// `SponsorPayout` — anyone drains `lamports` to `recipient`,
/// subject to a rate limit of one payout per
/// [`SponsorPool::MIN_SLOTS_BETWEEN_PAYOUTS`] slots.
///
/// Account layout:
///   [0] caller          (signer, any wallet)
///   [1] pool_pda        (writable, program-owned)
///   [2] recipient       (writable, system-owned)
///   [3] system_program  (only for symmetry; the lamport movement is
///                        handled via direct lamports manipulation,
///                        not a CPI, because the PDA is program-owned)
pub fn sponsor_payout(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    ix: &Instruction,
) -> ProgramResult {
    let [caller, pool_account, recipient_account, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !caller.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let _bump = verify_sponsor_pool_pda(pool_account, program_id)?;
    let Instruction::SponsorPayout {
        lamports,
        recipient,
    } = ix
    else {
        return Err(ProgramError::Custom(ERR_INSTRUCTION_MALFORMED));
    };
    if recipient_account.key.as_ref() != recipient.as_slice() {
        msg!("tardus: sponsor-payout recipient account mismatch");
        return Err(ProgramError::InvalidAccountData);
    }
    if *lamports == 0 {
        msg!("tardus: sponsor-payout zero lamports");
        return Err(ProgramError::Custom(ERR_INSTRUCTION_MALFORMED));
    }

    let clock = Clock::get()?;
    let mut pool = load_sponsor_pool(pool_account)?;
    let elapsed = clock.slot.saturating_sub(pool.last_payout_slot);
    if pool.last_payout_slot != 0 && elapsed < SponsorPool::MIN_SLOTS_BETWEEN_PAYOUTS {
        msg!(
            "tardus: sponsor-payout rate limit: only {} slots since last payout (min {})",
            elapsed,
            SponsorPool::MIN_SLOTS_BETWEEN_PAYOUTS
        );
        // Custom error code 30 = ERR_RATE_LIMIT.
        return Err(ProgramError::Custom(30));
    }
    if **pool_account.lamports.borrow() < *lamports {
        msg!(
            "tardus: sponsor-payout pool underfunded: have {}, want {}",
            **pool_account.lamports.borrow(),
            lamports
        );
        return Err(ProgramError::InsufficientFunds);
    }

    // Direct lamport movement: program-owned PDA lets us debit
    // without invoke_signed (PDA's account has program-modifiable
    // lamports balance because the PDA is owned by this program).
    **pool_account.lamports.borrow_mut() = pool_account
        .lamports()
        .saturating_sub(*lamports);
    **recipient_account.lamports.borrow_mut() = recipient_account
        .lamports()
        .saturating_add(*lamports);

    pool.last_payout_slot = clock.slot;
    pool.total_payouts = pool.total_payouts.saturating_add(*lamports);
    store_sponsor_pool(pool_account, &pool)?;

    msg!(
        "tardus: sponsor-payout lamports={} recipient={} slot={}",
        lamports,
        recipient_account.key,
        clock.slot
    );
    Ok(())
}
