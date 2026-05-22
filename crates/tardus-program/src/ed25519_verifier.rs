//! Ed25519 precompile bridge for Solana SBF (Faz 1.4.4).
//!
//! TARDUS's on-chain program cannot call `curve25519-dalek`'s variable-
//! base scalar multiplication at runtime — the lookup-table allocation
//! exceeds the 4 KB SBF stack budget (see `research/PRODUCTION_LESSONS.md`
//! §R8). Instead, signature verification is offloaded to the Solana
//! `ed25519_program` precompile via the standard instructions-sysvar
//! introspection pattern:
//!
//! 1. Caller submits a transaction with two instructions:
//!    - **Instruction 0** invokes `ed25519_program::id()` with a
//!      payload encoding `(joint_pk, coin_pubkey, signature)`.
//!    - **Instruction 1** invokes `tardus_program::Refresh` (or
//!      `Withdraw`), passing the instructions sysvar as an account.
//! 2. The Solana runtime executes instruction 0 first; if the
//!    precompile rejects the signature, the entire transaction
//!    aborts before instruction 1 runs.
//! 3. Instruction 1 reads the instructions sysvar, finds the
//!    preceding ed25519 precompile call, and validates that it
//!    operated on the expected `(pubkey, message, signature)` tuple
//!    (preventing a malicious caller from precompile-verifying a
//!    different signature than the one in the TARDUS instruction).
//!
//! The precompile's data layout for a single signature in the same
//! instruction is (all little-endian):
//!
//! ```text
//! offset  size  field
//!   0       1   num_signatures (must be 1)
//!   1       1   padding (must be 0)
//!   2       2   signature_offset (must be 16)
//!   4       2   signature_instruction_index (must be u16::MAX)
//!   6       2   public_key_offset (must be 80)
//!   8       2   public_key_instruction_index (must be u16::MAX)
//!  10       2   message_data_offset (must be 112)
//!  12       2   message_data_size (must equal message.len())
//!  14       2   message_instruction_index (must be u16::MAX)
//!  16      64   signature bytes (R || s)
//!  80      32   public key bytes
//! 112     ...   message bytes
//! ```

extern crate alloc;
#[allow(unused_imports)]
use alloc::format; // for `msg!` macro expansion
use solana_program::{
    account_info::AccountInfo,
    ed25519_program,
    msg,
    program_error::ProgramError,
    sysvar::instructions::{load_current_index_checked, load_instruction_at_checked},
};
use tardus_core::Signature;

const PRECOMPILE_HEADER_LEN: usize = 16;
const SIG_OFFSET: usize = 16;
const SIG_LEN: usize = 64;
const PK_OFFSET: usize = SIG_OFFSET + SIG_LEN;
const PK_LEN: usize = 32;
const MSG_OFFSET: usize = PK_OFFSET + PK_LEN;

// Custom error codes — distinct from `sbf_processor`'s 1-14 range.
const ERR_MISSING_PRECOMPILE: u32 = 30;
const ERR_WRONG_PRECOMPILE_PROGRAM: u32 = 31;
const ERR_PRECOMPILE_TOO_SHORT: u32 = 32;
const ERR_PRECOMPILE_BAD_HEADER: u32 = 33;
const ERR_PRECOMPILE_PK_MISMATCH: u32 = 34;
const ERR_PRECOMPILE_MSG_MISMATCH: u32 = 35;
const ERR_PRECOMPILE_SIG_MISMATCH: u32 = 36;
const ERR_PRECOMPILE_OFFSETS_INVALID: u32 = 37;

/// Read the instructions sysvar and validate that the preceding
/// instruction is an ed25519 precompile call that verified the
/// expected `(pubkey, message, signature)` tuple.
///
/// # Panics
/// Cannot panic: the `u16::try_from(SIG_OFFSET)` calls are over
/// compile-time constants ≤ 255, well within `u16::MAX`.
///
/// # Errors
/// Returns one of the `ERR_PRECOMPILE_*` custom errors if:
/// - There is no preceding instruction (`current_idx == 0`).
/// - The preceding instruction's program is not `ed25519_program::id()`.
/// - The precompile data is malformed or uses an unexpected layout.
/// - Any of `(pubkey, message, signature)` does not match the
///   expected values.
pub fn verify_ed25519_precompile(
    instructions_sysvar: &AccountInfo,
    expected_pubkey: &[u8; 32],
    expected_message: &[u8],
    expected_signature: &Signature,
) -> Result<(), ProgramError> {
    let current_idx = load_current_index_checked(instructions_sysvar)?;
    if current_idx == 0 {
        msg!("tardus: no preceding ed25519 precompile instruction");
        return Err(ProgramError::Custom(ERR_MISSING_PRECOMPILE));
    }
    let prev = load_instruction_at_checked(
        usize::from(current_idx - 1),
        instructions_sysvar,
    )?;

    if prev.program_id != ed25519_program::id() {
        msg!("tardus: preceding instruction is not ed25519 precompile");
        return Err(ProgramError::Custom(ERR_WRONG_PRECOMPILE_PROGRAM));
    }

    let data = &prev.data;
    let expected_msg_len = expected_message.len();
    let total_expected = MSG_OFFSET + expected_msg_len;
    if data.len() < total_expected {
        msg!(
            "tardus: ed25519 precompile data too short: {} < {}",
            data.len(),
            total_expected
        );
        return Err(ProgramError::Custom(ERR_PRECOMPILE_TOO_SHORT));
    }

    // Header validation.
    if data[0] != 1 || data[1] != 0 {
        return Err(ProgramError::Custom(ERR_PRECOMPILE_BAD_HEADER));
    }

    // SignatureOffsets validation — all data in-instruction with fixed positions.
    let sig_offset = u16::from_le_bytes([data[2], data[3]]);
    let sig_ix_idx = u16::from_le_bytes([data[4], data[5]]);
    let pk_offset = u16::from_le_bytes([data[6], data[7]]);
    let pk_ix_idx = u16::from_le_bytes([data[8], data[9]]);
    let msg_data_offset = u16::from_le_bytes([data[10], data[11]]);
    let msg_data_size = u16::from_le_bytes([data[12], data[13]]);
    let msg_ix_idx = u16::from_le_bytes([data[14], data[15]]);

    let expected_sig_offset = u16::try_from(SIG_OFFSET).expect("SIG_OFFSET fits u16");
    let expected_pk_offset = u16::try_from(PK_OFFSET).expect("PK_OFFSET fits u16");
    let expected_msg_offset = u16::try_from(MSG_OFFSET).expect("MSG_OFFSET fits u16");
    let expected_msg_size = u16::try_from(expected_msg_len)
        .map_err(|_| ProgramError::Custom(ERR_PRECOMPILE_OFFSETS_INVALID))?;
    if sig_offset != expected_sig_offset
        || sig_ix_idx != u16::MAX
        || pk_offset != expected_pk_offset
        || pk_ix_idx != u16::MAX
        || msg_data_offset != expected_msg_offset
        || msg_data_size != expected_msg_size
        || msg_ix_idx != u16::MAX
    {
        msg!("tardus: ed25519 precompile SignatureOffsets layout mismatch");
        return Err(ProgramError::Custom(ERR_PRECOMPILE_OFFSETS_INVALID));
    }

    // Validate the actual payload bytes match expectations.
    let actual_sig_r = &data[SIG_OFFSET..SIG_OFFSET + 32];
    let actual_sig_s = &data[SIG_OFFSET + 32..SIG_OFFSET + 64];
    let actual_pk = &data[PK_OFFSET..PK_OFFSET + PK_LEN];
    let actual_msg = &data[MSG_OFFSET..MSG_OFFSET + expected_msg_len];

    if actual_pk != expected_pubkey {
        msg!("tardus: ed25519 precompile pubkey mismatch");
        return Err(ProgramError::Custom(ERR_PRECOMPILE_PK_MISMATCH));
    }
    if actual_msg != expected_message {
        msg!("tardus: ed25519 precompile message mismatch");
        return Err(ProgramError::Custom(ERR_PRECOMPILE_MSG_MISMATCH));
    }
    if actual_sig_r != expected_signature.r || actual_sig_s != expected_signature.s {
        msg!("tardus: ed25519 precompile signature mismatch");
        return Err(ProgramError::Custom(ERR_PRECOMPILE_SIG_MISMATCH));
    }

    // Suppress unused warning on PRECOMPILE_HEADER_LEN by referencing here.
    debug_assert_eq!(PRECOMPILE_HEADER_LEN, 16);
    Ok(())
}
