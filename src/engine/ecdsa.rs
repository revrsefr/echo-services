//! ECDSA-NIST256P-CHALLENGE SASL: the account stores a NIST P-256 public key; the
//! server issues a random 32-byte challenge, the client returns a DER ECDSA signature
//! over it, verified here against the stored key. The private key never leaves the
//! client, so the mechanism is safe even without TLS. The 32-byte challenge is used
//! directly as the signed digest (its length matches the P-256 field size).

use base64::{engine::general_purpose::STANDARD, Engine as _};
use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};

/// The random challenge length, equal to the P-256 digest size.
pub const CHALLENGE_LEN: usize = 32;

/// Validate a base64 SEC1 public key (compressed or uncompressed P-256 point) and
/// return the normalized base64 to store, or `None` if it isn't a valid P-256 key.
pub fn validate_pubkey(b64: &str) -> Option<String> {
    let raw = STANDARD.decode(b64.trim()).ok()?;
    VerifyingKey::from_sec1_bytes(&raw).ok()?;
    Some(STANDARD.encode(&raw))
}

/// Verify a base64 DER ECDSA signature over `challenge` against the stored base64
/// SEC1 public key.
pub fn verify(pubkey_b64: &str, challenge: &[u8], sig_b64: &str) -> bool {
    let Some(pk) = STANDARD.decode(pubkey_b64).ok() else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_sec1_bytes(&pk) else {
        return false;
    };
    let Some(raw) = STANDARD.decode(sig_b64.trim()).ok() else {
        return false;
    };
    let Ok(sig) = Signature::from_der(&raw) else {
        return false;
    };
    vk.verify_prehash(challenge, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
    use rand_core::OsRng;

    #[test]
    fn challenge_signature_round_trip() {
        let sk = SigningKey::random(&mut OsRng);
        let pubkey = STANDARD.encode(sk.verifying_key().to_encoded_point(true).as_bytes());
        assert_eq!(validate_pubkey(&pubkey).as_deref(), Some(pubkey.as_str()));

        let challenge = [0x5au8; CHALLENGE_LEN];
        let sig: Signature = sk.sign_prehash(&challenge).unwrap();
        let sig_b64 = STANDARD.encode(sig.to_der().as_bytes());
        assert!(verify(&pubkey, &challenge, &sig_b64), "valid signature must verify");

        // a different challenge, a garbage signature, and a junk key all fail
        assert!(!verify(&pubkey, &[0u8; CHALLENGE_LEN], &sig_b64));
        assert!(!verify(&pubkey, &challenge, "not-base64!!"));
        assert!(validate_pubkey("aGVsbG8=").is_none());
    }
}
