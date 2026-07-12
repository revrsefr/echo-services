//! SCRAM (RFC 5802 / RFC 7677) server side for SASL SCRAM-SHA-256 and
//! SCRAM-SHA-512. Stored verifier format `v=1,i=,s=,sk=,sv=` where
//!
//!     SaltedPassword = Hi(password, salt, i)         (PBKDF2, dklen = hash len)
//!     ClientKey      = HMAC(SaltedPassword, "Client Key")
//!     StoredKey      = H(ClientKey)
//!     ServerKey      = HMAC(SaltedPassword, "Server Key")
//!
//! Passwords are used as raw UTF-8 (no SASLprep), matching that stack.

use argon2::password_hash::rand_core::{OsRng, RngCore};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;

// Provisioning cost. High on purpose: the client bears the Hi() work each login,
// the server only at REGISTER, and the verifier must not be a weaker
// password-equivalent than the argon2 hash beside it.
pub const DEFAULT_ITERATIONS: u32 = 1_200_000;
const SALT_LEN: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Hash {
    Sha256,
    Sha512,
}

impl Hash {
    pub fn from_mech(mech: &str) -> Option<Hash> {
        match mech {
            "SCRAM-SHA-256" => Some(Hash::Sha256),
            "SCRAM-SHA-512" => Some(Hash::Sha512),
            _ => None,
        }
    }

    pub fn mech(self) -> &'static str {
        match self {
            Hash::Sha256 => "SCRAM-SHA-256",
            Hash::Sha512 => "SCRAM-SHA-512",
        }
    }
}

// --- primitives, dispatched on the hash ---

pub(crate) fn hmac(hash: Hash, key: &[u8], msg: &[u8]) -> Vec<u8> {
    match hash {
        Hash::Sha256 => {
            let mut m = Hmac::<Sha256>::new_from_slice(key).expect("hmac takes any key length");
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }
        Hash::Sha512 => {
            let mut m = Hmac::<Sha512>::new_from_slice(key).expect("hmac takes any key length");
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }
    }
}

pub(crate) fn h(hash: Hash, data: &[u8]) -> Vec<u8> {
    match hash {
        Hash::Sha256 => Sha256::digest(data).to_vec(),
        Hash::Sha512 => Sha512::digest(data).to_vec(),
    }
}

// SaltedPassword = Hi(password, salt, i): PBKDF2 with dklen == the hash length
// (one output block, all SCRAM needs). Keys the HMAC once and iterates.
pub(crate) fn hi(hash: Hash, password: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    match hash {
        Hash::Sha256 => {
            let mut out = [0u8; 32];
            pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut out);
            out.to_vec()
        }
        Hash::Sha512 => {
            let mut out = [0u8; 64];
            pbkdf2::pbkdf2_hmac::<Sha512>(password, salt, iterations, &mut out);
            out.to_vec()
        }
    }
}

pub(crate) fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}

// --- verifier ---

pub struct Verifier {
    pub iterations: u32,
    pub salt: Vec<u8>,
    pub stored_key: Vec<u8>,
    pub server_key: Vec<u8>,
}

/// Compute and encode a fresh verifier for `password`.
pub fn make_verifier(hash: Hash, password: &str, iterations: u32) -> String {
    // A salt whose base64 avoids '+' and '/' keeps the verifier portable to
    // stricter parsers in the wider stack; 16 random bytes clear it quickly.
    let salt = loop {
        let mut s = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut s);
        let b64 = STANDARD.encode(s);
        if !b64.contains('+') && !b64.contains('/') {
            break s;
        }
    };
    let salted = hi(hash, password.as_bytes(), &salt, iterations);
    let stored_key = h(hash, &hmac(hash, &salted, b"Client Key"));
    let server_key = hmac(hash, &salted, b"Server Key");
    format!(
        "v=1,i={},s={},sk={},sv={}",
        iterations,
        STANDARD.encode(salt),
        STANDARD.encode(&stored_key),
        STANDARD.encode(&server_key),
    )
}

pub fn parse_verifier(encoded: &str) -> Option<Verifier> {
    let (mut iterations, mut salt, mut stored_key, mut server_key) = (None, None, None, None);
    for part in encoded.split(',') {
        let (k, v) = part.split_once('=')?;
        match k {
            "v" if v != "1" => return None,
            "v" => {}
            "i" => iterations = v.parse().ok(),
            "s" => salt = STANDARD.decode(v).ok(),
            "sk" => stored_key = STANDARD.decode(v).ok(),
            "sv" => server_key = STANDARD.decode(v).ok(),
            _ => {}
        }
    }
    Some(Verifier {
        iterations: iterations?,
        salt: salt?,
        stored_key: stored_key?,
        server_key: server_key?,
    })
}

// --- exchange ---

pub struct ClientFirst {
    pub username: String,
    pub gs2_header: String,
    pub client_first_bare: String,
    pub cnonce: String,
}

/// Parse `<cbflag>,<authzid>,n=<user>,r=<cnonce>`. Channel binding (`p=`) is
/// rejected — we advertise the bare mechanisms only.
pub fn parse_client_first(msg: &str) -> Option<ClientFirst> {
    let mut it = msg.splitn(3, ',');
    let cbflag = it.next()?;
    let authzid = it.next()?;
    let bare = it.next()?;
    if cbflag.starts_with('p') {
        return None;
    }
    let mut fields = bare.split(',');
    let username = fields.next()?.strip_prefix("n=")?;
    let cnonce = fields.next()?.strip_prefix("r=")?;
    Some(ClientFirst {
        username: username.replace("=2C", ",").replace("=3D", "="),
        gs2_header: format!("{cbflag},{authzid},"),
        client_first_bare: bare.to_string(),
        cnonce: cnonce.to_string(),
    })
}

fn nonce() -> String {
    let mut b = [0u8; 18];
    OsRng.fill_bytes(&mut b);
    STANDARD.encode(b) // base64 never contains ',', so it is a valid SCRAM value
}

/// Build the server-first message and return it with the full (combined) nonce.
pub fn server_first(cnonce: &str, v: &Verifier) -> (String, String) {
    let full_nonce = format!("{cnonce}{}", nonce());
    let msg = format!(
        "r={},s={},i={}",
        full_nonce,
        STANDARD.encode(&v.salt),
        v.iterations
    );
    (msg, full_nonce)
}

/// Verify the client-final message; on success return the server-final message
/// (`v=<ServerSignature>`) proving the server also knows the password.
pub fn verify_final(
    hash: Hash,
    v: &Verifier,
    client_first_bare: &str,
    server_first: &str,
    gs2_header: &str,
    full_nonce: &str,
    client_final: &str,
) -> Option<String> {
    let (without_proof, proof_b64) = client_final.rsplit_once(",p=")?;
    let proof = STANDARD.decode(proof_b64).ok()?;

    let (mut cbind, mut rnonce) = (None, None);
    for field in without_proof.split(',') {
        if let Some(x) = field.strip_prefix("c=") {
            cbind = Some(x);
        } else if let Some(x) = field.strip_prefix("r=") {
            rnonce = Some(x);
        }
    }
    if rnonce? != full_nonce {
        return None;
    }
    // c= must echo the GS2 header we saw in client-first (no channel binding).
    if STANDARD.decode(cbind?).ok()? != gs2_header.as_bytes() {
        return None;
    }

    let auth_message = format!("{client_first_bare},{server_first},{without_proof}");
    let client_signature = hmac(hash, &v.stored_key, auth_message.as_bytes());
    if proof.len() != client_signature.len() {
        return None;
    }
    let client_key = xor(&proof, &client_signature);
    // Constant-time: StoredKey is a secret, so leak nothing through compare timing.
    if h(hash, &client_key).ct_eq(&v.stored_key).unwrap_u8() != 1 {
        return None;
    }
    let server_signature = hmac(hash, &v.server_key, auth_message.as_bytes());
    Some(format!("v={}", STANDARD.encode(&server_signature)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7677 test vector (user "user", password "pencil").
    #[test]
    fn rfc7677_vector() {
        let salt = STANDARD.decode("W22ZaJ0SNY7soEsUEjb6gQ==").unwrap();
        let salted = hi(Hash::Sha256, b"pencil", &salt, 4096);
        let client_key = hmac(Hash::Sha256, &salted, b"Client Key");
        let stored_key = h(Hash::Sha256, &client_key);
        let server_key = hmac(Hash::Sha256, &salted, b"Server Key");
        let auth_message = "n=user,r=rOprNGfwEbeRWgbNEkqO,\
             r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,\
             c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
        let client_sig = hmac(Hash::Sha256, &stored_key, auth_message.as_bytes());
        let client_proof = xor(&client_key, &client_sig);
        let server_sig = hmac(Hash::Sha256, &server_key, auth_message.as_bytes());
        assert_eq!(STANDARD.encode(&client_proof), "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=");
        assert_eq!(STANDARD.encode(&server_sig), "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=");
    }

    // A full server-side exchange, playing the client with a fixed nonce, for
    // both hashes and a right/wrong password.
    fn run_exchange(hash: Hash, register_pw: &str, login_pw: &str) -> bool {
        let verifier = parse_verifier(&make_verifier(hash, register_pw, 4096)).unwrap();
        let cf = parse_client_first("n,,n=user,r=cnonce123").unwrap();
        let (server_first, full_nonce) = server_first(&cf.cnonce, &verifier);

        // Client computes its proof for login_pw against the server-provided salt/i.
        let salted = hi(hash, login_pw.as_bytes(), &verifier.salt, verifier.iterations);
        let client_key = hmac(hash, &salted, b"Client Key");
        let stored_key = h(hash, &client_key);
        let without_proof = format!("c=biws,r={full_nonce}");
        let auth_message = format!("{},{},{}", cf.client_first_bare, server_first, without_proof);
        let client_sig = hmac(hash, &stored_key, auth_message.as_bytes());
        let proof = xor(&client_key, &client_sig);
        let client_final = format!("{without_proof},p={}", STANDARD.encode(&proof));

        verify_final(hash, &verifier, &cf.client_first_bare, &server_first, &cf.gs2_header, &full_nonce, &client_final).is_some()
    }

    #[test]
    fn exchange_sha256_ok() {
        assert!(run_exchange(Hash::Sha256, "sesame", "sesame"));
    }

    #[test]
    fn exchange_sha512_ok() {
        assert!(run_exchange(Hash::Sha512, "sesame", "sesame"));
    }

    #[test]
    fn exchange_bad_password() {
        assert!(!run_exchange(Hash::Sha256, "sesame", "millet"));
        assert!(!run_exchange(Hash::Sha512, "sesame", "millet"));
    }

    #[test]
    fn channel_binding_rejected() {
        assert!(parse_client_first("p=tls-unique,,n=user,r=abc").is_none());
    }
}
