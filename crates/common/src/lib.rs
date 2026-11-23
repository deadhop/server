//! Conventions the deadhop services share: the watch-only wallet account and
//! its derivation, the names of the wallet's files, private files and the
//! service key, the rate limiter, and two small helpers. Moved verbatim from
//! deadhop's server, which re-exports everything at its old paths.

pub mod error;
pub mod files;
pub mod ratelimit;
pub mod wallet;

/// Recovery phrase, inside the wallet service's data directory.
pub const PHRASE_FILE: &str = "wallet.mnemonic";
/// Next to the xpub file: present once the wallet service has started.
pub const READY_FILE: &str = "ready";
/// Next to the xpub file: present when the xpub was generated here.
pub const GENERATED_FILE: &str = "generated";
/// Next to the xpub file: when the recovery phrase was last exported.
pub const EXPORTED_FILE: &str = "recovery-exported";

/// Seconds since the Unix epoch.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Resolves on SIGINT or SIGTERM.
pub async fn shutdown_signal() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("SIGTERM handler can be installed");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn the_clock_and_the_file_names_are_what_the_services_agree_on() {
        assert!(unix_now() > 1_700_000_000);
        assert_eq!(
            (PHRASE_FILE, READY_FILE, GENERATED_FILE, EXPORTED_FILE),
            ("wallet.mnemonic", "ready", "generated", "recovery-exported")
        );
    }

    /// Send `signal` to this process once `shutdown_signal` is waiting for it.
    async fn stops_on(signal: &str) {
        let waiting = tokio::spawn(shutdown_signal());
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!waiting.is_finished());
        let sent = std::process::Command::new("kill")
            .args([signal, &std::process::id().to_string()])
            .status()
            .unwrap();
        assert!(sent.success());
        tokio::time::timeout(Duration::from_secs(10), waiting)
            .await
            .expect("the signal ends the wait")
            .unwrap();
    }

    #[tokio::test]
    async fn an_interrupt_or_a_termination_request_ends_the_wait() {
        stops_on("-INT").await;
        stops_on("-TERM").await;
    }
}
