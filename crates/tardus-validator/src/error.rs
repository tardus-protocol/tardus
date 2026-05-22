//! Error types for the TARDUS validator daemon.

use thiserror::Error;

/// Top-level validator error.
#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("storage corruption: {0}")]
    StorageCorruption(String),

    #[error("AEAD encryption failure")]
    AeadFailure,

    #[error("HKDF expand failure")]
    HkdfFailure,

    #[error("share storage decode error: {0}")]
    ShareDecode(String),

    #[error("validator not initialised: no share at index {0}")]
    NoShare(u16),

    #[error("invalid configuration: {0}")]
    Config(String),
}

pub type Result<T> = core::result::Result<T, Error>;
