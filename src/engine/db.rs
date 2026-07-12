use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub name: String,
    pub password_hash: String,
    pub email: Option<String>,
    pub ts: u64,
}

// Event-sourced persistence: every change is an Event appended to a JSONL log,
// and account state is the fold of that log. Replicating this log across nodes
// is what turns the store federated later, without changing the services.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event")]
pub enum Event {
    AccountRegistered(Account),
}

pub enum RegError {
    Exists,
    Internal,
}

pub struct Db {
    accounts: HashMap<String, Account>, // keyed by casefolded name
    path: PathBuf,
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
                    Err(e) => tracing::warn!(%e, "skipping malformed event log line"),
                }
            }
        }
        tracing::info!(accounts = accounts.len(), ?path, "account store loaded");
        Self { accounts, path }
    }

    pub fn exists(&self, name: &str) -> bool {
        self.accounts.contains_key(&key(name))
    }

    pub fn register(&mut self, name: &str, password: &str, email: Option<String>) -> Result<(), RegError> {
        if self.exists(name) {
            return Err(RegError::Exists);
        }
        let password_hash = hash_password(password).ok_or(RegError::Internal)?;
        let account = Account { name: name.to_string(), password_hash, email, ts: now() };
        self.append(&Event::AccountRegistered(account.clone())).map_err(|_| RegError::Internal)?;
        self.accounts.insert(key(name), account);
        Ok(())
    }

    /// Check credentials; on success return the account's canonical name (its
    /// stored casing), else None.
    pub fn authenticate(&self, name: &str, password: &str) -> Option<&str> {
        let account = self.accounts.get(&key(name))?;
        verify_password(password, &account.password_hash).then_some(account.name.as_str())
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
