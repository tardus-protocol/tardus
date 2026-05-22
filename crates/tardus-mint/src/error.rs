//! Error type for `tardus-mint`.

use core::fmt;

/// Errors produced by mint-side operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A core primitive (signature, point, scalar) failed.
    Core(tardus_core::Error),

    /// A VSS share did not verify against the dealer's commitments.
    VssShareInvalid,

    /// A Schnorr proof-of-knowledge attached to a DKG round-1 message did not verify.
    PokInvalid,

    /// The qualified set after the complaint phase is smaller than the
    /// threshold `t`; the ceremony cannot complete and must be restarted.
    InsufficientQualifiedSet,

    /// A protocol round received a message tagged with the wrong
    /// ceremony or session identifier.
    DomainMismatch,

    /// A protocol round received a duplicate message from a participant.
    DuplicateParticipant,

    /// A protocol round received a message from a participant that is
    /// not part of the committee or signing set.
    UnknownParticipant,

    /// The protocol round received fewer messages than required to advance.
    InsufficientMessages,

    /// An HSM-enforced invariant was violated (e.g. nonce reuse under the
    /// same session identifier). Detection causes the violating
    /// validator to be removed via the revoke path of §3.8.
    NonceReuseDetected,

    /// A Lagrange interpolation coefficient could not be computed
    /// (signing set contained a duplicate or zero index).
    InvalidSigningSet,

    /// A proactive-reshare dealer broadcast a non-zero secret
    /// commitment (`Ã_0 ≠ identity`). The reshare polynomial must
    /// have `f̃(0) = 0` (§3.7); a non-zero commitment indicates a
    /// cheating dealer trying to shift the joint key.
    ResharePolyNonZero,
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
            Self::VssShareInvalid => f.write_str("VSS share did not verify against commitments"),
            Self::PokInvalid => f.write_str("proof of knowledge did not verify"),
            Self::InsufficientQualifiedSet => f.write_str(
                "qualified set after complaint phase smaller than threshold; ceremony aborted",
            ),
            Self::DomainMismatch => f.write_str("message tagged with wrong ceremony or session id"),
            Self::DuplicateParticipant => f.write_str("duplicate message from participant"),
            Self::UnknownParticipant => f.write_str("message from unknown participant"),
            Self::InsufficientMessages => f.write_str("insufficient messages to advance round"),
            Self::NonceReuseDetected => f.write_str("nonce reuse violation under same session id"),
            Self::InvalidSigningSet => f.write_str("invalid signing set (duplicate or zero index)"),
            Self::ResharePolyNonZero => f.write_str(
                "proactive reshare dealer's secret commitment is non-zero (Ã_0 ≠ identity)",
            ),
        }
    }
}

/// Result alias for mint-side operations.
pub type Result<T> = core::result::Result<T, Error>;
