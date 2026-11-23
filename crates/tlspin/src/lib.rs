//! TLS with pinned certificates: a rustls certificate verifier that accepts
//! only certificates with given SHA-256 fingerprints (for servers with
//! self-signed certificates), helpers to read and write fingerprints, and the
//! client settings that use it. The public API exposes only rustls types.
//! Moved verbatim from deadhop's `electrum.rs`.

use std::sync::Arc;

use bitcoin::hashes::{sha256, Hash};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

/// Parse a certificate fingerprint: 64 hex digits, colons allowed.
pub fn parse_fingerprint(s: &str) -> Option<[u8; 32]> {
    let hex: String = s.trim().chars().filter(|c| *c != ':').collect();
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex, &mut out).ok()?;
    Some(out)
}

/// SHA-256 of a DER certificate, as lowercase hex.
pub fn fingerprint_hex(der: &[u8]) -> String {
    hex::encode(sha256::Hash::hash(der).to_byte_array())
}

/// Accepts exactly the pinned certificates, ignoring names and authorities,
/// but still makes the server prove it holds the certificate's private key.
/// Without pins it accepts any certificate and records it (only used to
/// read a server's fingerprint).
#[derive(Debug)]
pub struct PinnedCert {
    pub pins: Option<Vec<[u8; 32]>>,
    pub seen: std::sync::Mutex<Option<[u8; 32]>>,
    pub algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let fp = sha256::Hash::hash(end_entity.as_ref()).to_byte_array();
        *self.seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(fp);
        match &self.pins {
            Some(pins) if !pins.contains(&fp) => Err(rustls::Error::General(format!(
                "certificate {} does not match the pinned fingerprint",
                hex::encode(fp)
            ))),
            _ => Ok(ServerCertVerified::assertion()),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

pub fn tls_config(verifier: Option<Arc<PinnedCert>>) -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports the default protocol versions");
    match verifier {
        Some(v) => builder
            .dangerous()
            .with_custom_certificate_verifier(v)
            .with_no_client_auth(),
        None => {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            builder.with_root_certificates(roots).with_no_client_auth()
        }
    }
}

pub fn pinned(pins: Option<Vec<[u8; 32]>>) -> Arc<PinnedCert> {
    Arc::new(PinnedCert {
        pins,
        seen: std::sync::Mutex::new(None),
        algs: rustls::crypto::ring::default_provider().signature_verification_algorithms,
    })
}
