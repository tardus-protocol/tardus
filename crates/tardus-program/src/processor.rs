//! Instruction processors (spec §5.3).
//!
//! Each function takes plain Rust references to the in-memory account
//! state and applies the instruction. Pure functions; no Solana
//! runtime dependencies. The runtime wrapper in v1.4.2 will load
//! account data, call into these processors, and serialise the
//! mutated state back to account storage.

use sha2::{Digest, Sha256};
use tardus_core::{schnorr_verify, PublicKey, Signature};

use crate::{
    error::{Error, Result},
    instruction::Instruction,
    state::{KeysetEntry, KeysetRegistry, KeysetStatus, NullifierSet, Vault},
};

/// Domain separator for nullifier computation (matches §4.2 v1.4.3).
pub const NULLIFIER_DOMAIN: &[u8] = b"TARDUS-nullifier-v1";

/// Compute nullifier from a coin's public commitment.
///
/// v1.4.3 spec: `null(Cp) = SHA-256("TARDUS-nullifier-v1" || Cp_bytes)`.
/// The earlier `null(x)` formulation required on-chain derivation of
/// `Cp = x · G`, which is incompatible with the Solana SBF stack
/// budget. See `research/PRODUCTION_LESSONS.md` §R8.
#[must_use]
pub fn compute_nullifier(coin_pubkey: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(NULLIFIER_DOMAIN);
    h.update(coin_pubkey);
    let out = h.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    bytes
}

// =====================================================================
// RegisterKeyset
// =====================================================================

/// Process a [`Instruction::RegisterKeyset`].
///
/// # Errors
/// - [`Error::KeysetAlreadyRegistered`] on duplicate `keyset_id`.
/// - [`Error::KeysetRegistryFull`] if capacity reached.
/// - [`Error::InstructionMalformed`] if not a register-keyset variant.
pub fn process_register_keyset(
    registry: &mut KeysetRegistry,
    ix: &Instruction,
) -> Result<()> {
    let Instruction::RegisterKeyset {
        keyset_id,
        denom,
        joint_pk,
        epoch,
        authorization: _,
    } = ix
    else {
        return Err(Error::InstructionMalformed);
    };

    // Threshold-signature authorization verification deferred to
    // v1.4.2 (requires committee MIK registry, which is itself an
    // account in v1.4.2). v1: skip authorization check, marked TODO.

    if registry.find(keyset_id).is_some() {
        return Err(Error::KeysetAlreadyRegistered);
    }
    if registry.entries.len() >= crate::state::KEYSET_REGISTRY_CAPACITY {
        return Err(Error::KeysetRegistryFull);
    }

    registry.entries.push(KeysetEntry {
        keyset_id: *keyset_id,
        denom: *denom,
        joint_pk: *joint_pk,
        epoch: *epoch,
        status: KeysetStatus::Active,
    });

    Ok(())
}

// =====================================================================
// Deposit
// =====================================================================

/// Process an [`Instruction::Deposit`].
///
/// # Errors
/// - [`Error::DepositAmountMismatch`] if `lamports != denom`.
/// - [`Error::UnknownKeysetId`] / [`Error::KeysetRevoked`] if no active keyset for `denom`.
/// - [`Error::InstructionMalformed`] if not a deposit variant.
pub fn process_deposit(
    registry: &KeysetRegistry,
    vault: &mut Vault,
    ix: &Instruction,
) -> Result<()> {
    let Instruction::Deposit { denom, lamports } = ix else {
        return Err(Error::InstructionMalformed);
    };
    if denom != lamports {
        return Err(Error::DepositAmountMismatch);
    }
    if vault.denom != *denom {
        return Err(Error::VaultInvariantViolation);
    }
    let entry = registry
        .find_active_for_denom(*denom)
        .ok_or(Error::UnknownKeysetId)?;
    if entry.status != KeysetStatus::Active {
        return Err(Error::KeysetRevoked);
    }
    vault.collateral = vault
        .collateral
        .checked_add(*lamports)
        .ok_or(Error::VaultInvariantViolation)?;
    Ok(())
}

// =====================================================================
// Refresh
// =====================================================================

/// Process an [`Instruction::Refresh`].
///
/// Verifies the surrendered coin's signature, computes its nullifier,
/// and inserts the nullifier into the set. The new coins emerge
/// off-chain via the round-6 unblinding of §4.5; they are *not* part
/// of the on-chain refresh transaction.
///
/// # Errors
/// - [`Error::UnknownKeysetId`] / [`Error::KeysetRevoked`].
/// - [`Error::CoinSignatureInvalid`] / [`Error::Core`].
/// - [`Error::DoubleSpend`].
pub fn process_refresh(
    registry: &KeysetRegistry,
    nullifiers: &mut NullifierSet,
    ix: &Instruction,
) -> Result<[u8; 32]> {
    let Instruction::Refresh {
        coin_pubkey,
        coin_signature,
        denom,
    } = ix
    else {
        return Err(Error::InstructionMalformed);
    };

    verify_coin_for_spend(registry, *denom, coin_pubkey, coin_signature)?;
    let nullifier = compute_nullifier(coin_pubkey);

    if !nullifiers.insert(nullifier) {
        return Err(Error::DoubleSpend);
    }
    Ok(nullifier)
}

// =====================================================================
// Withdraw
// =====================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WithdrawOutcome {
    pub nullifier: [u8; 32],
    pub recipient: [u8; 32],
    pub lamports_released: u64,
}

/// Process an [`Instruction::Withdraw`].
///
/// # Errors
/// Same shape as `process_refresh`, plus:
/// - [`Error::VaultInsufficientCollateral`] if vault < denom.
pub fn process_withdraw(
    registry: &KeysetRegistry,
    vault: &mut Vault,
    nullifiers: &mut NullifierSet,
    ix: &Instruction,
) -> Result<WithdrawOutcome> {
    let Instruction::Withdraw {
        coin_pubkey,
        coin_signature,
        denom,
        recipient,
    } = ix
    else {
        return Err(Error::InstructionMalformed);
    };
    if vault.denom != *denom {
        return Err(Error::VaultInvariantViolation);
    }
    verify_coin_for_spend(registry, *denom, coin_pubkey, coin_signature)?;
    let nullifier = compute_nullifier(coin_pubkey);
    if !nullifiers.insert(nullifier) {
        return Err(Error::DoubleSpend);
    }
    if vault.collateral < *denom {
        return Err(Error::VaultInsufficientCollateral);
    }
    vault.collateral -= denom;
    Ok(WithdrawOutcome {
        nullifier,
        recipient: *recipient,
        lamports_released: *denom,
    })
}

// =====================================================================
// Revoke
// =====================================================================

/// Process an [`Instruction::Revoke`].
///
/// # Errors
/// - [`Error::UnknownKeysetId`].
/// - [`Error::InstructionMalformed`].
pub fn process_revoke(registry: &mut KeysetRegistry, ix: &Instruction) -> Result<()> {
    let Instruction::Revoke {
        keyset_id,
        authorization: _,
    } = ix
    else {
        return Err(Error::InstructionMalformed);
    };
    // Threshold-signature verification deferred to v1.4.2.
    let entry = registry
        .find_mut(keyset_id)
        .ok_or(Error::UnknownKeysetId)?;
    entry.status = KeysetStatus::Revoked;
    Ok(())
}

// =====================================================================
// Shared verification
// =====================================================================

fn verify_coin_for_spend(
    registry: &KeysetRegistry,
    denom: u64,
    coin_pubkey: &[u8; 32],
    coin_signature: &Signature,
) -> Result<()> {
    let entry = registry
        .find_active_for_denom(denom)
        .ok_or(Error::UnknownKeysetId)?;
    if entry.status != KeysetStatus::Active {
        return Err(Error::KeysetRevoked);
    }

    // v1.4.3 bearer model: the user-supplied `coin_pubkey` is the
    // canonical identifier of the coin; the on-chain program does
    // not derive it from a secret. Sanity-check that the bytes
    // decode to a valid point in the prime-order subgroup, then
    // verify the mint signature against (joint_pk, coin_pubkey).
    PublicKey::from_bytes(coin_pubkey).map_err(Error::Core)?;
    let joint_pk = PublicKey::from_bytes(&entry.joint_pk).map_err(Error::Core)?;

    let ok = schnorr_verify(&joint_pk, coin_pubkey, coin_signature).map_err(Error::Core)?;
    if !ok {
        return Err(Error::CoinSignatureInvalid);
    }
    Ok(())
}
