//! Error type for `tardus-refresh`.

use core::fmt;

/// Errors produced by refresh-side operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A core primitive failed.
    Core(tardus_core::Error),

    /// A mint-side primitive failed.
    Mint(tardus_mint::Error),

    /// The supplied coin's `pubkey_bytes` does not match `secret · G`.
    CoinPubkeyMismatch,

    /// A coin's signature did not verify under the supplied joint key.
    CoinSignatureInvalid,

    /// Cut-and-choose challenge index was out of `[1, κ]`.
    ChallengeOutOfRange,

    /// Round-4 reveal verification failed for at least one revealed
    /// candidate; the user is being detected as cheating.
    CheatingDetected,

    /// A protocol round received a message tagged with the wrong
    /// session identifier.
    SessionIdMismatch,

    /// Internal state inconsistency.
    InvalidState,
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

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(e) => write!(f, "core primitive error: {e}"),
            Self::Mint(e) => write!(f, "mint primitive error: {e}"),
            Self::CoinPubkeyMismatch => f.write_str("coin pubkey does not match secret"),
            Self::CoinSignatureInvalid => f.write_str("coin signature does not verify"),
            Self::ChallengeOutOfRange => f.write_str("cut-and-choose challenge index out of range"),
            Self::CheatingDetected => {
                f.write_str("reveal verification failed; user is cheating")
            }
            Self::SessionIdMismatch => f.write_str("session id mismatch across rounds"),
            Self::InvalidState => f.write_str("internal state inconsistency"),
        }
    }
}

/// Result alias for refresh-side operations.
pub type Result<T> = core::result::Result<T, Error>;
