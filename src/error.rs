//! Error type shared by every layer of the service.

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can go wrong. Variants map one-to-one to stable wire codes.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
    #[error("proof of work rejected: {0}")]
    Pow(String),
    #[error("rate limit exceeded")]
    RateLimited,
    #[error("not authorized")]
    Unauthorized,
    #[error("invoice not found")]
    NotFound,
    #[error("service at capacity")]
    Capacity,
    #[error("invoicing is stopped by the operator")]
    Paused,
    #[error("service temporarily unavailable")]
    Unavailable,
    #[error("chain backend: {0}")]
    Chain(String),
    #[error("storage: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("transport: {0}")]
    Transport(String),
}

impl From<deadhop_netengine::error::Error> for Error {
    fn from(e: deadhop_netengine::error::Error) -> Self {
        use deadhop_netengine::error::Error as Engine;
        match e {
            Engine::InvalidParams(why) => Error::InvalidParams(why),
            Engine::RateLimited => Error::RateLimited,
            // What this service told the engine comes back as it was.
            Engine::Host(e) => match e.downcast::<Error>() {
                Ok(own) => *own,
                Err(other) => Error::Transport(other.to_string()),
            },
        }
    }
}

/// This service's error, to hand to the network engine and get back unchanged.
pub fn to_engine(e: Error) -> deadhop_netengine::error::Error {
    deadhop_netengine::error::Error::Host(Box::new(e))
}

impl From<deadhop_common::error::Error> for Error {
    fn from(e: deadhop_common::error::Error) -> Self {
        match e {
            deadhop_common::error::Error::Config(why) => Error::Config(why),
            deadhop_common::error::Error::Capacity => Error::Capacity,
            deadhop_common::error::Error::Chain(why) => Error::Chain(why),
            deadhop_common::error::Error::Io(e) => Error::Io(e),
        }
    }
}

impl From<deadhop_electrum::error::Error> for Error {
    fn from(e: deadhop_electrum::error::Error) -> Self {
        match e {
            deadhop_electrum::error::Error::Config(why) => Error::Config(why),
            deadhop_electrum::error::Error::Chain(why) => Error::Chain(why),
        }
    }
}

impl From<deadhop_net::error::Error> for Error {
    fn from(e: deadhop_net::error::Error) -> Self {
        let deadhop_net::error::Error::InvalidParams(why) = e;
        Error::InvalidParams(why)
    }
}

impl From<contextvm_sdk::Error> for Error {
    fn from(e: contextvm_sdk::Error) -> Self {
        Error::Transport(e.to_string())
    }
}

impl Error {
    /// Stable machine-readable code sent to clients.
    pub fn code(&self) -> &'static str {
        match self {
            Error::InvalidParams(_) => "invalid_params",
            Error::Pow(_) => "pow_rejected",
            Error::RateLimited => "rate_limited",
            Error::Unauthorized => "unauthorized",
            Error::NotFound => "not_found",
            Error::Capacity => "capacity",
            Error::Paused => "paused",
            Error::Unavailable => "unavailable",
            Error::Config(_) | Error::Chain(_) | Error::Db(_) | Error::Io(_) | Error::Transport(_) => "internal",
        }
    }

    /// Message that is safe to send to an untrusted caller. Internal failures
    /// are collapsed so that paths, SQL and backend addresses never leak.
    pub fn public_message(&self) -> String {
        match self.code() {
            "internal" => "internal error".to_string(),
            _ => self.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_error_handed_to_the_network_engine_comes_back_as_it_was() {
        use deadhop_netengine::error::Error as Engine;
        let own: Vec<Error> = vec![
            Error::Config("c".into()),
            Error::InvalidParams("p".into()),
            Error::Pow("w".into()),
            Error::RateLimited,
            Error::Unauthorized,
            Error::NotFound,
            Error::Capacity,
            Error::Paused,
            Error::Unavailable,
            Error::Chain("x".into()),
            Error::Db(rusqlite::Error::InvalidQuery),
            Error::Io(std::io::Error::other("disk")),
            Error::Transport("t".into()),
        ];
        for e in own {
            let (variant, code, text) = (std::mem::discriminant(&e), e.code(), e.to_string());
            let through = to_engine(e);
            assert_eq!(through.to_string(), text, "the engine shows the host's own text");
            let back = Error::from(through);
            assert_eq!(
                (std::mem::discriminant(&back), back.code(), back.to_string()),
                (variant, code, text)
            );
        }
        // The engine's own refusals keep their variant and text.
        let refused = Error::from(Engine::InvalidParams("bad".into()));
        assert!(matches!(&refused, Error::InvalidParams(m) if m == "bad"));
        assert_eq!(refused.to_string(), "invalid parameters: bad");
        assert!(matches!(Error::from(Engine::RateLimited), Error::RateLimited));
        assert_eq!(Engine::RateLimited.to_string(), Error::RateLimited.to_string());
        // Something that is not this service's error is an internal failure.
        let foreign = Error::from(Engine::Host(Box::new(std::io::Error::other("elsewhere"))));
        assert!(matches!(&foreign, Error::Transport(m) if m == "elsewhere"));
        assert_eq!(foreign.public_message(), "internal error");
    }

    #[test]
    fn shared_crate_errors_keep_their_variant_and_text() {
        use deadhop_common::error::Error as Common;
        let io = Common::Io(std::io::Error::other("disk"));
        let cases: Vec<(Error, &str, &str)> = vec![
            (
                Common::Config("x".into()).into(),
                "internal",
                "invalid configuration: x",
            ),
            (Common::Capacity.into(), "capacity", "service at capacity"),
            (Common::Chain("x".into()).into(), "internal", "chain backend: x"),
            (io.into(), "internal", "io: disk"),
        ];
        for (e, code, text) in cases {
            assert_eq!((e.code(), e.to_string().as_str()), (code, text));
        }
        assert!(matches!(Error::from(Common::Capacity), Error::Capacity));
        assert!(matches!(Error::from(Common::Chain("x".into())), Error::Chain(_)));
    }

    #[test]
    fn transport_errors_convert() {
        let e: Error = contextvm_sdk::Error::Transport("relay gone".into()).into();
        assert!(matches!(&e, Error::Transport(m) if m.contains("relay gone")));
        assert_eq!(e.public_message(), "internal error");
    }

    #[test]
    fn codes_and_public_messages() {
        let io = Error::Io(std::io::Error::other("/secret/path"));
        let db = Error::Db(rusqlite::Error::InvalidQuery);
        let cases: Vec<(Error, &str)> = vec![
            (Error::InvalidParams("x".into()), "invalid_params"),
            (Error::Pow("x".into()), "pow_rejected"),
            (Error::RateLimited, "rate_limited"),
            (Error::Unauthorized, "unauthorized"),
            (Error::NotFound, "not_found"),
            (Error::Capacity, "capacity"),
            (Error::Paused, "paused"),
            (Error::Unavailable, "unavailable"),
            (Error::Config("x".into()), "internal"),
            (Error::Chain("10.0.0.1 refused".into()), "internal"),
            (Error::Transport("x".into()), "internal"),
            (io, "internal"),
            (db, "internal"),
        ];
        for (e, code) in cases {
            assert_eq!(e.code(), code);
            if code == "internal" {
                assert_eq!(e.public_message(), "internal error");
            } else {
                assert_eq!(e.public_message(), e.to_string());
            }
        }
    }
}
