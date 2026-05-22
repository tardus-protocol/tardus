//! Error type for `tardus-core`.

use core::fmt;

/// Errors produced by core primitives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A 32-byte sequence did not decode to a valid edwards25519 point
    /// in the prime-order subgroup.
    InvalidPoint,

    /// A 32-byte sequence was not a canonical encoding of an element of
    /// the scalar field `F_l`.
    InvalidScalar,

    /// A signature failed verification.
    InvalidSignature,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPoint => f.write_str("invalid curve point encoding"),
            Self::InvalidScalar => f.write_str("non-canonical scalar encoding"),
            Self::InvalidSignature => f.write_str("signature verification failed"),
        }
    }
}

/// Result alias for `tardus-core` operations.
pub type Result<T> = core::result::Result<T, Error>;
