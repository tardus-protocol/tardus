use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid recipient pubkey: {0}")]
    BadRecipient(String),

    #[error("inbox full for recipient (max {max} messages)")]
    InboxFull { max: usize },

    #[error("payload too large ({size} bytes, max {max})")]
    PayloadTooLarge { size: usize, max: usize },

    #[error("message not found")]
    NotFound,
}

pub type Result<T> = core::result::Result<T, Error>;
