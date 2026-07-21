//! Optional TLS for the ircd uplink (#370). The link cert is typically self-signed,
//! so instead of a CA we authenticate the server by pinning its SPKIFP — the base64
//! SHA256 of its SubjectPublicKeyInfo (which, unlike a whole-cert fingerprint,
//! survives a certificate renewal that keeps the same key). The normal PASS
//! handshake still runs inside the TLS channel.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use base64::Engine;
use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::crypto::{self, CryptoProvider};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
use tokio_rustls::TlsConnector;

use crate::config::Uplink;

/// The SPKIFP of a certificate: base64(SHA256(SubjectPublicKeyInfo DER)).
pub fn spki_fingerprint(cert: &CertificateDer) -> Result<String> {
    use x509_cert::der::{Decode, Encode};
    let parsed = x509_cert::Certificate::from_der(cert.as_ref())?;
    let spki = parsed.tbs_certificate.subject_public_key_info.to_der()?;
    let digest = <sha2::Sha256 as sha2::Digest>::digest(&spki);
    Ok(base64::engine::general_purpose::STANDARD.encode(digest))
}

// Accept the server iff its SPKIFP matches the pinned value; the handshake
// signature is still verified against that key by the crypto provider, so only the
// holder of the pinned key can complete the connection.
#[derive(Debug)]
struct SpkiPin {
    expected: String,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for SpkiPin {
    fn verify_server_cert(&self, end_entity: &CertificateDer, _intermediates: &[CertificateDer], _server_name: &ServerName, _ocsp: &[u8], _now: UnixTime) -> Result<ServerCertVerified, Error> {
        let got = spki_fingerprint(end_entity).map_err(|e| Error::General(format!("uplink cert unreadable: {e}")))?;
        if got == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::General("uplink SPKI fingerprint does not match the pinned value".into()))
        }
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// A TLS connector + server name for the uplink, or `None` when TLS is off.
pub fn connector(uplink: &Uplink) -> Result<Option<(TlsConnector, ServerName<'static>)>> {
    if !uplink.tls {
        return Ok(None);
    }
    if uplink.spki_fingerprint.is_empty() {
        return Err(anyhow!("uplink.tls is set but uplink.spki_fingerprint is empty"));
    }
    // Install a process-default provider if nothing else did yet (idempotent).
    let _ = crypto::aws_lc_rs::default_provider().install_default();
    let provider = Arc::new(crypto::aws_lc_rs::default_provider());
    let verifier = Arc::new(SpkiPin { expected: uplink.spki_fingerprint.clone(), provider });
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let name = ServerName::try_from(uplink.host.clone())?;
    Ok(Some((TlsConnector::from(Arc::new(config)), name)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The SPKIFP matches `openssl x509 -pubkey | openssl pkey -pubin -outform DER |
    // openssl dgst -sha256 -binary | base64` for this fixed self-signed cert.
    #[test]
    fn spki_fingerprint_matches_openssl() {
        let der = base64::engine::general_purpose::STANDARD.decode(
            "MIIDCTCCAfGgAwIBAgIUJf3uwnHdwpCANK0wddShifEEProwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJZWNoby10ZXN0MB4XDTI2MDcyMTEzNDIxNFoXDTI2MDcyMzEzNDIxNFowFDESMBAGA1UEAwwJZWNoby10ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu/L8m2F/7ELMezgktDchrlVGh6VQpT+uatXG0IvVPOS9BNm60xLAaijEvv7oI1paWCBM4EKpRPhZH5Of5xyBNtvfpyUdLKKeS5NiRNrGQJwXU0wz8j1Wrwe6qyffWPBO3RlBd+PvRLgCGlE1oV5gyw+TkjCo+9eLNgwIVIJP5/HCmEohSgtpOjqOthzVt/DjwfaH8VUbHC9r718cNfj1stfL46wW/sevQThmqEwFshOWxGKPbcJNhlpcC/LXr6YO2RwlzGnF2AEkvC7ZzG4dKCDZNYYgOgR7sKFcUArBE+4mvKQBcG1qDj4GBLeH82n0jRZSf0f6EpHjKCPTkvnJswIDAQABo1MwUTAdBgNVHQ4EFgQU6cgHWvusLXkexbuZ/9KOtzexegMwHwYDVR0jBBgwFoAU6cgHWvusLXkexbuZ/9KOtzexegMwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAbuujq+xvRbRlq+FXC2PHhWlyCqHPEn7rKC7vr77rdXIMVxAzY3rlAfHgyTgL41XrDsx58dfKswUp3g2VxJZHwKXQhoCKRWo+fAxJ6bHVWXrPkJJYZtI/JtggKNcORWw6VT0081UhXaRANDlGHMQ+MfTr3NaNz+aIAMhMtL4BSobSocjn4eAUaFxXVF0yznT8+U8MiGMgThOLrnyvzg9NK7D4iNf3gC1XRyD1RHP6w7ji/tpmLR4CQ6A3i2ywYD8ZQilBQhBa2abzP7zxHbQe8wHbopWPaz5QQ34bxpZ8MLKgY2OqzNndqt8+ZUYv9uk8AllnBT/fQbWC1b02B8gNMQ==",
        ).unwrap();
        let cert = CertificateDer::from(der);
        assert_eq!(spki_fingerprint(&cert).unwrap(), "Wh/ag/dtBCpXhiYPhRWV66kx3FutmTyNw1dysTbWvao=");
    }
}
