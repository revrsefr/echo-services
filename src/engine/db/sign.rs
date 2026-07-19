// Per-origin Ed25519 signatures for gossiped (Global) log entries — the Tier C
// federation trust model (see docs/federation.md). Each node signs the entries it
// authors; peers verify against the author origin's public key, so a peer can only
// assert records for an origin whose private key it holds. Entirely optional: with
// no `[gossip.signing]` configured, entries are unsigned and this is inert.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use super::Event;

// The bytes a signature covers: everything that fixes the entry's identity and
// content. `serde_json` is deterministic for the Global event set (all `Vec`/scalar
// fields — no unordered maps), so sender and receiver derive the same bytes.
fn payload(origin: &str, seq: u64, lamport: u64, event: &Event) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(origin.as_bytes());
    v.push(0);
    v.extend_from_slice(&seq.to_le_bytes());
    v.extend_from_slice(&lamport.to_le_bytes());
    v.push(0);
    v.extend_from_slice(serde_json::to_string(event).unwrap_or_default().as_bytes());
    v
}

// A node's signing configuration: its own key (to sign what it authors) plus the
// public keys it trusts, keyed by origin SID (to verify what it ingests).
pub struct Signing {
    signer: SigningKey,
    trust: HashMap<String, VerifyingKey>,
}

impl Signing {
    // Build from base64 config: this node's 32-byte secret key, and a map of
    // origin -> its 32-byte public key. Errors describe the offending field.
    pub fn new(secret_b64: &str, trust_b64: &HashMap<String, String>) -> Result<Self, String> {
        let secret = B64.decode(secret_b64.trim()).map_err(|_| "gossip.signing.key is not valid base64".to_string())?;
        let bytes: [u8; 32] = secret.as_slice().try_into().map_err(|_| "gossip.signing.key must be 32 bytes".to_string())?;
        let signer = SigningKey::from_bytes(&bytes);
        let mut trust = HashMap::new();
        for (origin, pk_b64) in trust_b64 {
            let raw = B64.decode(pk_b64.trim()).map_err(|_| format!("gossip.signing.trust key for {origin} is not valid base64"))?;
            let arr: [u8; 32] = raw.as_slice().try_into().map_err(|_| format!("gossip.signing.trust key for {origin} must be 32 bytes"))?;
            let vk = VerifyingKey::from_bytes(&arr).map_err(|_| format!("gossip.signing.trust key for {origin} is not a valid ed25519 public key"))?;
            trust.insert(origin.clone(), vk);
        }
        Ok(Signing { signer, trust })
    }

    // Sign an entry we're authoring; base64 of the 64-byte signature.
    pub fn sign(&self, origin: &str, seq: u64, lamport: u64, event: &Event) -> String {
        B64.encode(self.signer.sign(&payload(origin, seq, lamport, event)).to_bytes())
    }

    // True if `sig` is a valid signature over the entry by the trusted key for its
    // origin. False if the origin isn't trusted, the signature is missing, or it
    // doesn't verify (`verify_strict` also rejects malleable/degenerate signatures).
    pub fn verify(&self, origin: &str, seq: u64, lamport: u64, event: &Event, sig: Option<&str>) -> bool {
        let Some(vk) = self.trust.get(origin) else { return false };
        let Some(sig) = sig else { return false };
        let Ok(raw) = B64.decode(sig.trim()) else { return false };
        let Ok(bytes) = <[u8; 64]>::try_from(raw.as_slice()) else { return false };
        vk.verify_strict(&payload(origin, seq, lamport, event), &Signature::from_bytes(&bytes)).is_ok()
    }
}

// A fresh keypair as (secret_b64, public_b64), for the `--gen-gossip-key` CLI.
pub fn generate() -> (String, String) {
    let signer = SigningKey::generate(&mut rand_core::OsRng);
    (B64.encode(signer.to_bytes()), B64.encode(signer.verifying_key().to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::db::Event;

    fn ev() -> Event {
        Event::AccountDropped { account: "alice".into() }
    }

    #[test]
    fn sign_then_verify_roundtrips_and_rejects_tampering() {
        let (sec, pubk) = generate();
        let trust = HashMap::from([("A".to_string(), pubk)]);
        let s = Signing::new(&sec, &trust).unwrap();

        let sig = s.sign("A", 3, 4, &ev());
        assert!(s.verify("A", 3, 4, &ev(), Some(&sig)), "a genuine signature verifies");
        // Any change to the covered fields invalidates it.
        assert!(!s.verify("A", 4, 4, &ev(), Some(&sig)), "a different seq is rejected");
        assert!(!s.verify("A", 3, 4, &Event::AccountDropped { account: "bob".into() }, Some(&sig)), "a different event is rejected");
        assert!(!s.verify("A", 3, 4, &ev(), None), "a missing signature is rejected");
        assert!(!s.verify("B", 3, 4, &ev(), Some(&sig)), "an untrusted origin is rejected");
    }

    #[test]
    fn a_forged_key_does_not_verify() {
        let (sec_a, pub_a) = generate();
        let (sec_b, _pub_b) = generate();
        // We trust A's key; B tries to forge an entry claiming origin A.
        let s = Signing::new(&sec_a, &HashMap::from([("A".to_string(), pub_a)])).unwrap();
        let forger = Signing::new(&sec_b, &HashMap::new()).unwrap();
        let forged = forger.sign("A", 1, 1, &ev());
        assert!(!s.verify("A", 1, 1, &ev(), Some(&forged)), "a signature from the wrong key is rejected");
    }
}
