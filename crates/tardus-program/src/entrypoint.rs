//! Solana SBF entrypoint and instruction dispatch (Faz 1.4.2).
//!
//! This module wires the v1 pure-Rust processors (`processor.rs`) to
//! the Solana BPF runtime. The entrypoint deserialises the
//! [`crate::instruction::Instruction`] from the program data and
//! delegates to the appropriate handler in [`crate::sbf_processor`].
//!
//! ## Build modes
//!
//! - **SBF target** (`cargo build-sbf`): the `solana_program::entrypoint!`
//!   macro exports `entrypoint` as the program's loader symbol.
//! - **Host target** (`cargo build`): the macro is no-op; the
//!   handlers can still be unit-tested via the helper APIs in
//!   `crate::sbf_processor`.
//! - **`no-entrypoint` feature**: suppresses the entrypoint macro,
//!   allowing this crate to be embedded as a library in off-chain
//!   tooling (CLI, tests) without symbol collisions.

// `format!` is brought into scope via the entrypoint macro expansion
// from sibling `alloc`; we re-import to make the dependency explicit.
extern crate alloc;
#[allow(unused_imports)]
use alloc::format;
use borsh::BorshDeserialize;
use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, msg, program_error::ProgramError,
    pubkey::Pubkey,
};

use crate::{instruction::Instruction, sbf_processor};

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

/// Program-level instruction dispatcher.
///
/// # Errors
/// - [`ProgramError::InvalidInstructionData`] if the instruction
///   payload fails Borsh deserialisation.
/// - Various [`ProgramError`] variants surfaced by the individual
///   handlers in [`crate::sbf_processor`].
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let ix = Instruction::try_from_slice(instruction_data).map_err(|_| {
        msg!("tardus: instruction deserialisation failed");
        ProgramError::InvalidInstructionData
    })?;

    match &ix {
        Instruction::RegisterKeyset { .. } => {
            sbf_processor::register_keyset(program_id, accounts, &ix)
        }
        Instruction::Deposit { .. } => sbf_processor::deposit(program_id, accounts, &ix),
        Instruction::Refresh { .. } => sbf_processor::refresh(program_id, accounts, &ix),
        Instruction::Withdraw { .. } => sbf_processor::withdraw(program_id, accounts, &ix),
        Instruction::Revoke { .. } => sbf_processor::revoke(program_id, accounts, &ix),
        Instruction::Bootstrap { .. } => sbf_processor::bootstrap(program_id, accounts, &ix),
        Instruction::SponsorDeposit { .. } => {
            sbf_processor::sponsor_deposit(program_id, accounts, &ix)
        }
        Instruction::SponsorPayout { .. } => {
            sbf_processor::sponsor_payout(program_id, accounts, &ix)
        }
        Instruction::ResizeAccount { .. } => {
            sbf_processor::resize_account(program_id, accounts, &ix)
        }
    }
}
