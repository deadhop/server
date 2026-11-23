//! What the network engine refuses, and what its host refused or failed at.

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// The first two variants and their text match the service's own error,
/// which it converts into. The third carries the host's own error through
/// the engine untouched, so the host gets back exactly what it gave.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
    #[error("rate limit exceeded")]
    RateLimited,
    #[error("{0}")]
    Host(Box<dyn std::error::Error + Send + Sync>),
}

impl From<deadhop_net::error::Error> for Error {
    fn from(e: deadhop_net::error::Error) -> Self {
        let deadhop_net::error::Error::InvalidParams(why) = e;
        Error::InvalidParams(why)
    }
}
