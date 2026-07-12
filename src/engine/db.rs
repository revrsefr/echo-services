use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use serde::{Deserialize, Serialize};

use super::scram::{self, Hash};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub name: String,
    pub password_hash: String,
    pub email: Option<String>,
    pub ts: u64,
    // SCRAM verifiers (`v=1,i=,s=,sk=,sv=`), computed from the password at
    // registration. Absent on accounts registered before SCRAM support.
    #[serde(default)]
    pub scram256: Option<String>,
    #[serde(default)]
    pub scram512: Option<String>,
    // TLS client-certificate fingerprints (lowercase hex) that may log in to
    // this account via SASL EXTERNAL. Each fingerprint maps to one account.
    #[serde(default)]
    pub certfps: Vec<String>,
}

// Event-sourced persistence: every change is an Event appended to a JSONL log,
// and account state is the fold of that log. Replicating this log across nodes
// is what turns the store federated later, without changing the services.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event")]
pub enum Event {
    AccountRegistered(Account),
    CertAdded { account: String, fp: String },
    CertRemoved { account: String, fp: String },
}

#[derive(Debug)]
pub enum RegError {
    Exists,
    Internal,
}

#[derive(Debug)]
pub enum CertError {
    Invalid,    // not a plausible fingerprint
    InUse,      // already registered (to any account)
    NoAccount,  // target account does not exist
    Internal,   // persistence failed
}

// A fingerprint is hex (hash digest), optionally colon-separated. Bound the
// length so a junk value can't bloat an account.
fn valid_fp(fp: &str) -> bool {
    let hex = fp.chars().filter(|c| *c != ':').count();
    (32..=128).contains(&hex) && fp.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
}

// The expensive, password-derived half of an account, computed once at
// registration. Split out from `register` so the derivation (argon2 + two SCRAM
// verifiers, ~1s at the default cost) can run off the reactor via spawn_blocking.
pub struct Credentials {
    password_hash: String,
    scram256: String,
    scram512: String,
}

pub struct Db {
    accounts: HashMap<String, Account>, // keyed by casefolded name
    path: PathBuf,
    // PBKDF2 cost baked into new SCRAM verifiers; lowered by tests.
    pub(crate) scram_iterations: u32,
}

fn key(name: &str) -> String {
    name.to_ascii_lowercase()
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Db {
    pub fn open(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let mut accounts = HashMap::new();
        if let Ok(data) = std::fs::read_to_string(&path) {
            for line in data.lines().filter(|l| !l.trim().is_empty()) {
                match serde_json::from_str::<Event>(line) {
                    Ok(Event::AccountRegistered(a)) => {
                        accounts.insert(key(&a.name), a);
                    }
                    Ok(Event::CertAdded { account, fp }) => {
                        if let Some(a) = accounts.get_mut(&key(&account)) {
                            a.certfps.push(fp);
                        }
                    }
                    Ok(Event::CertRemoved { account, fp }) => {
                        if let Some(a) = accounts.get_mut(&key(&account)) {
                            a.certfps.retain(|c| *c != fp);
                        }
                    }
                    Err(e) => tracing::warn!(%e, "skipping malformed event log line"),
                }
            }
        }
        tracing::info!(accounts = accounts.len(), ?path, "account store loaded");
        Self { accounts, path, scram_iterations: scram::DEFAULT_ITERATIONS }
    }

    pub fn exists(&self, name: &str) -> bool {
        self.accounts.contains_key(&key(name))
    }

    /// Derive the password-bound half of an account. Pure and CPU-heavy (no
    /// `&self`), so a caller can run it on a blocking thread; the cheap
    /// `register_prepared` then commits the result.
    pub fn derive_credentials(password: &str, iterations: u32) -> Option<Credentials> {
        Some(Credentials {
            password_hash: hash_password(password)?,
            scram256: scram::make_verifier(Hash::Sha256, password, iterations),
            scram512: scram::make_verifier(Hash::Sha512, password, iterations),
        })
    }

    /// Commit pre-derived credentials as a new account. Cheap: no key stretching.
    pub fn register_prepared(&mut self, name: &str, creds: Credentials, email: Option<String>) -> Result<(), RegError> {
        if self.exists(name) {
            return Err(RegError::Exists);
        }
        let account = Account {
            name: name.to_string(),
            password_hash: creds.password_hash,
            email,
            ts: now(),
            scram256: Some(creds.scram256),
            scram512: Some(creds.scram512),
            certfps: Vec::new(),
        };
        self.append(&Event::AccountRegistered(account.clone())).map_err(|_| RegError::Internal)?;
        self.accounts.insert(key(name), account);
        Ok(())
    }

    /// Register synchronously, deriving and committing in one call. A test helper;
    /// the live paths derive off-thread via `derive_credentials` + `register_prepared`.
    #[cfg(test)]
    pub fn register(&mut self, name: &str, password: &str, email: Option<String>) -> Result<(), RegError> {
        let creds = Self::derive_credentials(password, self.scram_iterations).ok_or(RegError::Internal)?;
        self.register_prepared(name, creds, email)
    }

    /// Check credentials; on success return the account's canonical name (its
    /// stored casing), else None.
    pub fn authenticate(&self, name: &str, password: &str) -> Option<&str> {
        let account = self.accounts.get(&key(name))?;
        verify_password(password, &account.password_hash).then_some(account.name.as_str())
    }

    /// The account's canonical name and its SCRAM verifier for `mech`, if any.
    pub fn scram_lookup(&self, name: &str, mech: &str) -> Option<(&str, &str)> {
        let account = self.accounts.get(&key(name))?;
        let verifier = match mech {
            "SCRAM-SHA-256" => account.scram256.as_deref(),
            "SCRAM-SHA-512" => account.scram512.as_deref(),
            _ => None,
        }?;
        Some((account.name.as_str(), verifier))
    }

    /// The canonical name of the account owning `fp`, if any. Fingerprints are
    /// globally unique, so this is unambiguous.
    pub fn certfp_owner(&self, fp: &str) -> Option<&str> {
        let fp = fp.to_ascii_lowercase();
        self.accounts.values().find(|a| a.certfps.iter().any(|c| *c == fp)).map(|a| a.name.as_str())
    }

    /// The fingerprints registered to an account (empty if unknown/none).
    pub fn certfps(&self, account: &str) -> &[String] {
        self.accounts.get(&key(account)).map_or(&[], |a| a.certfps.as_slice())
    }

    /// Register `fp` to `account`. Fingerprints are one-to-one with accounts.
    pub fn certfp_add(&mut self, account: &str, fp: &str) -> Result<(), CertError> {
        let fp = fp.to_ascii_lowercase();
        if !valid_fp(&fp) {
            return Err(CertError::Invalid);
        }
        if self.certfp_owner(&fp).is_some() {
            return Err(CertError::InUse);
        }
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return Err(CertError::NoAccount);
        }
        self.append(&Event::CertAdded { account: account.to_string(), fp: fp.clone() }).map_err(|_| CertError::Internal)?;
        self.accounts.get_mut(&k).unwrap().certfps.push(fp);
        Ok(())
    }

    /// Remove `fp` from `account`. Ok(false) if the account had no such fingerprint.
    pub fn certfp_del(&mut self, account: &str, fp: &str) -> Result<bool, CertError> {
        let fp = fp.to_ascii_lowercase();
        let k = key(account);
        match self.accounts.get(&k) {
            None => return Err(CertError::NoAccount),
            Some(a) if !a.certfps.iter().any(|c| *c == fp) => return Ok(false),
            Some(_) => {}
        }
        self.append(&Event::CertRemoved { account: account.to_string(), fp: fp.clone() }).map_err(|_| CertError::Internal)?;
        self.accounts.get_mut(&k).unwrap().certfps.retain(|c| *c != fp);
        Ok(true)
    }

    fn append(&self, event: &Event) -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&self.path)?;
        writeln!(f, "{}", serde_json::to_string(event).unwrap_or_default())
    }
}

fn hash_password(password: &str) -> Option<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default().hash_password(password.as_bytes(), &salt).ok().map(|h| h.to_string())
}

fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .map(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
        .unwrap_or(false)
}
