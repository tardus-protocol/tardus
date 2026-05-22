//! Error type for `tardus-client`.

use core::fmt;

/// Errors produced by client-side wallet operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// A core primitive failed.
    Core(tardus_core::Error),

    /// A mint-side primitive failed.
    Mint(tardus_mint::Error),

    /// A refresh-side primitive failed.
    Refresh(tardus_refresh::Error),

    /// The invoice URI is malformed (wrong scheme, missing parameter,
    /// invalid hex, exceeded length bound, etc.).
    InvalidInvoice(InvoiceParseError),

    /// AEAD seal or open failed.
    AeadFailure,

    /// The coin store does not contain the requested coin.
    CoinNotFound,

    /// The coin store already contains a coin with the same nullifier
    /// (double-receipt detected).
    DuplicateCoin,

    /// The coin's signature does not verify under the supplied joint
    /// public key.
    CoinSignatureInvalid,

    /// Backup ciphertext failed validation (wrong key, corruption,
    /// or wrong AEAD additional-data).
    BackupValidationFailed,
}

/// Granular invoice parse errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvoiceParseError {
    WrongScheme,
    MissingRecipient,
    InvalidRecipientHex,
    MissingDenom,
    InvalidDenom,
    InvalidRelayUrl,
    MemoTooLong,
    MemoNotBase64,
}

impl From<tardus_core::Error> for Error {
    fn from(value: tardus_core::Error) -> Self {
        Self::Core(value)
    }
}

impl From<tardus_mint::Error> for Error {
    fn from(value: tardus_mint::Error) -> Self {
        Self::Mint(value)
    }
}

impl From<tardus_refresh::Error> for Error {
    fn from(value: tardus_refresh::Error) -> Self {
        Self::Refresh(value)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(e) => write!(f, "core primitive error: {e}"),
            Self::Mint(e) => write!(f, "mint primitive error: {e}"),
            Self::Refresh(e) => write!(f, "refresh primitive error: {e}"),
            Self::InvalidInvoice(p) => write!(f, "invalid invoice: {p:?}"),
            Self::AeadFailure => f.write_str("AEAD seal or open failed"),
            Self::CoinNotFound => f.write_str("coin not in store"),
            Self::DuplicateCoin => f.write_str("coin already present (double-receipt)"),
            Self::CoinSignatureInvalid => f.write_str("coin signature does not verify"),
            Self::BackupValidationFailed => f.write_str("backup ciphertext validation failed"),
        }
    }
}

/// Result alias for client-side operations.
pub type Result<T> = core::result::Result<T, Error>;
