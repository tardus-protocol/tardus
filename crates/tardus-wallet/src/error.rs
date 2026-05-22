//! Error types for the TARDUS wallet SDK.

use thiserror::Error;

/// All wallet-layer failure modes. The inner crates
/// (`tardus_core` / `tardus_mint` / `tardus_refresh`) target `no_std`
/// and don't implement `std::error::Error`, so we hand-write the
/// `From` impls and the `Display` formatting rather than using
/// thiserror's `#[from]` shortcut.
#[derive(Debug, Error)]
pub enum Error {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON decode failed: {0}")]
    Json(#[from] serde_json::Error),

    #[error("validator returned HTTP {status}: {body}")]
    ValidatorRejected { status: u16, body: String },

    #[error("hex decode failed: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("expected {expected} bytes for {label}, got {got}")]
    BadLength {
        label: &'static str,
        expected: usize,
        got: usize,
    },

    #[error("validator returned `from_index` {got}, expected {expected}")]
    UnexpectedIndex { expected: u16, got: u16 },

    #[error("tardus-core error: {0:?}")]
    Core(tardus_core::Error),

    #[error("tardus-mint error: {0:?}")]
    Mint(tardus_mint::Error),

    #[error("tardus-refresh error: {0:?}")]
    Refresh(tardus_refresh::Error),

    #[error("tardus-client error: {0:?}")]
    Client(tardus_client::Error),
}

impl From<tardus_core::Error> for Error {
    fn from(e: tardus_core::Error) -> Self {
        Self::Core(e)
    }
}

impl From<tardus_mint::Error> for Error {
    fn from(e: tardus_mint::Error) -> Self {
        Self::Mint(e)
    }
}

impl From<tardus_refresh::Error> for Error {
    fn from(e: tardus_refresh::Error) -> Self {
        Self::Refresh(e)
    }
}

impl From<tardus_client::Error> for Error {
    fn from(e: tardus_client::Error) -> Self {
        Self::Client(e)
    }
}

pub type Result<T> = core::result::Result<T, Error>;
