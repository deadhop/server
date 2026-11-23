//! What can go wrong with the chain backend or its address.

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// The variants and their text match the service's own error, which it converts into.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("chain backend: {0}")]
    Chain(String),
}
