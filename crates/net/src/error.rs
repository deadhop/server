//! What can go wrong here that is the caller's doing. Connection failures
//! are reported in the transport's and the relay pool's own error types.

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// The variant and its text match the service's own error, which it converts into.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
}
