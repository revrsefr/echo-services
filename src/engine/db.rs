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

// A durable record: the event plus the metadata a gossip layer needs to address
// and order it — the origin node, its per-node sequence (`origin:seq` is the
// cluster-unique id), and a Lamport clock for causal ordering across nodes.
// Lines written before these existed default them in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    #[serde(default)]
    origin: String,
    #[serde(default)]
    seq: u64,
    #[serde(default)]
    lamport: u64,
    #[serde(flatten)]
    event: Event,
}

// Append-only log, the sole persistent source of truth: `open` replays it,
// `append` stamps and writes a locally-authored entry, and `ingest` folds in an
// entry authored by another node. The version vector (highest seq applied per
// origin) plus the Lamport clock are the seam a future gossip layer ships entries
// over — de-duplicating and ordering them — without the services knowing.
pub struct EventLog {
    path: PathBuf,
    origin: String,
    lamport: u64,                   // logical clock, ticked on every event
    versions: HashMap<String, u64>, // per-origin highest seq applied (version vector)
}

impl EventLog {
    fn open(path: PathBuf, origin: String) -> (Self, Vec<Event>) {
        let mut events = Vec::new();
        let mut lamport = 0;
        let mut versions: HashMap<String, u64> = HashMap::new();
        if let Ok(data) = std::fs::read_to_string(&path) {
            for line in data.lines().filter(|l| !l.trim().is_empty()) {
                match serde_json::from_str::<LogEntry>(line) {
                    Ok(entry) => {
                        lamport = lamport.max(entry.lamport);
                        versions.entry(entry.origin.clone()).and_modify(|s| *s = (*s).max(entry.seq)).or_insert(entry.seq);
                        events.push(entry.event);
                    }
                    Err(e) => tracing::warn!(%e, "skipping malformed event log line"),
                }
            }
        }
        (Self { path, origin, lamport, versions }, events)
    }

    // Seq the next locally-authored event will carry (0-based, per our origin).
    fn next_seq(&self) -> u64 {
        self.versions.get(&self.origin).map_or(0, |s| s + 1)
    }

    // Stamp a locally-authored event with the next seq + a ticked Lamport clock,
    // then persist it.
    fn append(&mut self, event: Event) -> std::io::Result<()> {
        self.lamport += 1;
        let entry = LogEntry { origin: self.origin.clone(), seq: self.next_seq(), lamport: self.lamport, event };
        self.persist(&entry)?;
        self.versions.insert(entry.origin.clone(), entry.seq);
        Ok(())
    }

    // Ingest an entry authored by another node — the gossip seam. Returns the
    // event to fold into state, or None if already applied (idempotent, so
    // re-delivery converges). Assumes per-origin in-order delivery.
    #[allow(dead_code)]
    fn ingest(&mut self, entry: LogEntry) -> std::io::Result<Option<Event>> {
        if self.versions.get(&entry.origin).is_some_and(|&s| entry.seq <= s) {
            return Ok(None); // already have it
        }
        self.persist(&entry)?;
        self.lamport = self.lamport.max(entry.lamport) + 1; // Lamport receive rule
        self.versions.insert(entry.origin.clone(), entry.seq);
        Ok(Some(entry.event))
    }

    fn persist(&self, entry: &LogEntry) -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&self.path)?;
        writeln!(f, "{}", serde_json::to_string(entry).unwrap_or_default())
    }
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
    log: EventLog,
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
    pub fn open(path: impl Into<PathBuf>, origin: impl Into<String>) -> Self {
        let (log, events) = EventLog::open(path.into(), origin.into());
        let mut accounts = HashMap::new();
        for event in events {
            apply(&mut accounts, event);
        }
        tracing::info!(accounts = accounts.len(), "account store loaded");
        Self { accounts, log, scram_iterations: scram::DEFAULT_ITERATIONS }
    }

    /// Fold an entry authored by another node into the store — the services-side
    /// of the gossip seam. Idempotent (re-delivered entries are dropped).
    #[allow(dead_code)]
    pub fn ingest(&mut self, entry: LogEntry) -> std::io::Result<()> {
        if let Some(event) = self.log.ingest(entry)? {
            apply(&mut self.accounts, event);
        }
        Ok(())
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
        self.log.append(Event::AccountRegistered(account.clone())).map_err(|_| RegError::Internal)?;
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
        self.log.append(Event::CertAdded { account: account.to_string(), fp: fp.clone() }).map_err(|_| CertError::Internal)?;
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
        self.log.append(Event::CertRemoved { account: account.to_string(), fp: fp.clone() }).map_err(|_| CertError::Internal)?;
        self.accounts.get_mut(&k).unwrap().certfps.retain(|c| *c != fp);
        Ok(true)
    }
}

// Fold one event into the account map. Shared by log replay (`open`) and gossip
// ingest, so both routes reconstruct identical state.
fn apply(accounts: &mut HashMap<String, Account>, event: Event) {
    match event {
        Event::AccountRegistered(a) => {
            accounts.insert(key(&a.name), a);
        }
        Event::CertAdded { account, fp } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                a.certfps.push(fp);
            }
        }
        Event::CertRemoved { account, fp } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                a.certfps.retain(|c| *c != fp);
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("fedserv-log-{name}.jsonl"));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn cert(account: &str, fp: &str) -> Event {
        Event::CertAdded { account: account.into(), fp: fp.into() }
    }

    // Locally-authored events get an incrementing per-origin seq and a ticking
    // Lamport clock.
    #[test]
    fn append_stamps_monotonic_metadata() {
        let (mut log, ev) = EventLog::open(tmp("append"), "nodeA".into());
        assert!(ev.is_empty());
        log.append(cert("x", "f1")).unwrap();
        log.append(cert("x", "f2")).unwrap();
        assert_eq!(log.versions.get("nodeA"), Some(&1)); // seqs 0 then 1
        assert_eq!(log.lamport, 2);
        assert_eq!(log.next_seq(), 2);
    }

    // Reopening the log recovers the clocks so seqs are never reused.
    #[test]
    fn reopen_recovers_clocks() {
        let p = tmp("reopen");
        {
            let (mut log, _) = EventLog::open(p.clone(), "nodeA".into());
            log.append(cert("x", "f1")).unwrap();
            log.append(cert("x", "f2")).unwrap();
        }
        let (log, events) = EventLog::open(p, "nodeA".into());
        assert_eq!(events.len(), 2);
        assert_eq!(log.next_seq(), 2);
        assert_eq!(log.lamport, 2);
    }

    // Ingesting a peer's entry applies it once and advances the Lamport clock;
    // a re-delivered entry is dropped (gossip convergence).
    #[test]
    fn ingest_is_idempotent() {
        let (mut log, _) = EventLog::open(tmp("ingest"), "local".into());
        let entry = LogEntry { origin: "peer".into(), seq: 0, lamport: 5, event: cert("x", "f") };
        assert!(log.ingest(entry.clone()).unwrap().is_some(), "first ingest applies");
        assert_eq!(log.versions.get("peer"), Some(&0));
        assert_eq!(log.lamport, 6, "receive rule: max(local, remote) + 1");
        assert!(log.ingest(entry).unwrap().is_none(), "duplicate ingest is a no-op");
    }

    // The gossip seam folds a peer's account into local state.
    #[test]
    fn db_ingest_folds_peer_account() {
        let mut db = Db::open(tmp("dbingest"), "local");
        db.scram_iterations = 4096;
        db.register("alice", "pw", None).unwrap();
        let bob = Account {
            name: "bob".into(), password_hash: "x".into(), email: None,
            ts: 0, scram256: None, scram512: None, certfps: vec![],
        };
        let entry = LogEntry { origin: "peer".into(), seq: 0, lamport: 1, event: Event::AccountRegistered(bob) };
        db.ingest(entry).unwrap();
        assert!(db.exists("bob"), "peer's account is present locally");
        assert!(db.exists("alice"), "local account still there");
    }
}
