//! Error type for `tardus-program`.

use core::fmt;

/// Errors produced by the on-chain program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A core primitive failed.
    Core(tardus_core::Error),

    /// The supplied keyset identifier is not registered.
    UnknownKeysetId,

    /// The keyset is registered but currently revoked.
    KeysetRevoked,

    /// The keyset registry already contains an entry with the given id.
    KeysetAlreadyRegistered,

    /// The keyset registry has reached its capacity.
    KeysetRegistryFull,

    /// A coin's mint signature does not verify against the registered
    /// joint public key.
    CoinSignatureInvalid,

    /// The coin's claimed pubkey does not match `secret · G`.
    CoinPubkeyMismatch,

    /// The submitted nullifier already exists in the tree (double-spend).
    DoubleSpend,

    /// The deposit amount does not match the denomination.
    DepositAmountMismatch,

    /// Refresh denomination preservation is violated:
    /// `Σ new_coins.denom != melted.denom`.
    RefreshDenominationMismatch,

    /// The vault has insufficient collateral to satisfy the withdrawal.
    VaultInsufficientCollateral,

    /// The vault collateral invariant is violated.
    VaultInvariantViolation,

    /// Threshold signature authorization is insufficient
    /// (e.g. fewer than `t` valid transcript signatures).
    InsufficientThresholdAuth,

    /// Strict-deserialisation rejected the instruction.
    InstructionMalformed,
}

impl From<tardus_core::Error> for Error {
    fn from(value: tardus_core::Error) -> Self {
        Self::Core(value)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(e) => write!(f, "core primitive error: {e}"),
            Self::UnknownKeysetId => f.write_str("unknown keyset id"),
            Self::KeysetRevoked => f.write_str("keyset is revoked"),
            Self::KeysetAlreadyRegistered => f.write_str("keyset already registered"),
            Self::KeysetRegistryFull => f.write_str("keyset registry full"),
            Self::CoinSignatureInvalid => f.write_str("coin signature does not verify"),
            Self::CoinPubkeyMismatch => f.write_str("coin pubkey does not match secret"),
            Self::DoubleSpend => f.write_str("nullifier already present (double-spend)"),
            Self::DepositAmountMismatch => f.write_str("deposit amount does not match denomination"),
            Self::RefreshDenominationMismatch => {
                f.write_str("refresh denomination preservation violated")
            }
            Self::VaultInsufficientCollateral => f.write_str("vault has insufficient collateral"),
            Self::VaultInvariantViolation => f.write_str("vault collateral invariant violated"),
            Self::InsufficientThresholdAuth => {
                f.write_str("insufficient threshold authorisation signatures")
            }
            Self::InstructionMalformed => f.write_str("instruction failed strict deserialisation"),
        }
    }
}

/// Result alias for program-side operations.
pub type Result<T> = core::result::Result<T, Error>;
