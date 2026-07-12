use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use super::scram::{self, Hash};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub name: String,
    pub password_hash: String,
    pub email: Option<String>,
    pub ts: u64,
    // The node that first registered this account (its "home"). With `ts` it
    // deterministically resolves a concurrent registration of the same name across
    // the federation. Named `home` not `origin` so it can't collide with the log
    // envelope's `origin` when this struct is flattened into a LogEntry. Defaulted
    // for records written before this existed.
    #[serde(default)]
    pub home: String,
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
    AccountEmailSet { account: String, email: Option<String> },
    AccountPasswordSet { account: String, password_hash: String, scram256: String, scram512: String },
    AccountDropped { account: String },
    NickGrouped { nick: String, account: String },
    NickUngrouped { nick: String },
    ChannelRegistered { name: String, founder: String, ts: u64 },
    ChannelDropped { name: String },
    ChannelMlock { name: String, on: String, off: String },
    ChannelAccessAdd { channel: String, account: String, level: String },
    ChannelAccessDel { channel: String, account: String },
    ChannelAkickAdd { channel: String, mask: String, reason: String },
    ChannelAkickDel { channel: String, mask: String },
    ChannelFounderSet { channel: String, founder: String },
    ChannelDescSet { channel: String, desc: String },
    ChannelEntryMsgSet { channel: String, msg: String },
}

// Whether an event replicates across the federation. Account identity is Global
// (one owner, gossiped everywhere); channel state is Local (scoped to the one
// network that authored it, so a node can't be handed ownership of a channel it
// never saw registered). Exhaustive on purpose: a new event must pick a side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    Global,
    Local,
}

impl Event {
    fn scope(&self) -> Scope {
        match self {
            Event::AccountRegistered(_)
            | Event::CertAdded { .. }
            | Event::CertRemoved { .. }
            | Event::AccountEmailSet { .. }
            | Event::AccountPasswordSet { .. }
            | Event::AccountDropped { .. }
            | Event::NickGrouped { .. }
            | Event::NickUngrouped { .. } => Scope::Global,
            Event::ChannelRegistered { .. }
            | Event::ChannelDropped { .. }
            | Event::ChannelMlock { .. }
            | Event::ChannelAccessAdd { .. }
            | Event::ChannelAccessDel { .. }
            | Event::ChannelAkickAdd { .. }
            | Event::ChannelAkickDel { .. }
            | Event::ChannelFounderSet { .. }
            | Event::ChannelDescSet { .. }
            | Event::ChannelEntryMsgSet { .. } => Scope::Local,
        }
    }
}

// An access-list entry: an account and its level ("op" or "voice").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChanAccess {
    pub account: String,
    pub level: String,
}

// An auto-kick entry: a nick!user@host mask and why it was added.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChanAkick {
    pub mask: String,
    pub reason: String,
}

// A registered channel and who owns it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelInfo {
    pub name: String,
    pub founder: String,
    pub ts: u64,
    // Mode-lock: chars services keep set / unset (besides the implicit +r).
    #[serde(default)]
    pub lock_on: String,
    #[serde(default)]
    pub lock_off: String,
    #[serde(default)]
    pub access: Vec<ChanAccess>,
    #[serde(default)]
    pub akick: Vec<ChanAkick>,
    // Free-text description, shown in INFO.
    #[serde(default)]
    pub desc: String,
    // Message noticed to users as they join.
    #[serde(default)]
    pub entrymsg: String,
}

impl ChannelInfo {
    /// The status mode to give `account` on join, if any: +o for the founder and
    /// access-list ops, +v for voices.
    pub fn join_mode(&self, account: &str) -> Option<&'static str> {
        if self.founder.eq_ignore_ascii_case(account) {
            return Some("+o");
        }
        self.access
            .iter()
            .find(|a| a.account.eq_ignore_ascii_case(account))
            .map(|a| if a.level == "voice" { "+v" } else { "+o" })
    }

    /// Whether `account` has operator access (founder or access-list op).
    pub fn is_op(&self, account: &str) -> bool {
        self.join_mode(account) == Some("+o")
    }

    /// The matching auto-kick entry for `hostmask` (nick!user@host), if any.
    pub fn akick_match(&self, hostmask: &str) -> Option<&ChanAkick> {
        self.akick.iter().find(|k| glob_match(&k.mask, hostmask))
    }

    /// The mode string services keep applied: +r plus the lock.
    pub fn lock_modes(&self) -> String {
        let mut s = format!("+r{}", self.lock_on);
        if !self.lock_off.is_empty() {
            s.push('-');
            s.push_str(&self.lock_off);
        }
        s
    }

    /// Given a mode change, the modes to send back to restore the lock, if it was
    /// violated. +r is always locked on. Only simple (paramless) modes are checked.
    pub fn enforce(&self, change: &str) -> Option<String> {
        let (mut readd, mut reremove) = (String::new(), String::new());
        let mut adding = true;
        for ch in change.chars() {
            match ch {
                '+' => adding = true,
                '-' => adding = false,
                m if m.is_ascii_alphabetic() => {
                    if (m == 'r' || self.lock_on.contains(m)) && !adding && !readd.contains(m) {
                        readd.push(m);
                    } else if self.lock_off.contains(m) && adding && !reremove.contains(m) {
                        reremove.push(m);
                    }
                }
                _ => {}
            }
        }
        if readd.is_empty() && reremove.is_empty() {
            return None;
        }
        let mut s = String::new();
        if !readd.is_empty() {
            s.push('+');
            s.push_str(&readd);
        }
        if !reremove.is_empty() {
            s.push('-');
            s.push_str(&reremove);
        }
        Some(s)
    }
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

#[cfg(test)]
impl LogEntry {
    pub(crate) fn for_test(origin: &str, seq: u64, lamport: u64, event: Event) -> Self {
        LogEntry { origin: origin.to_string(), seq, lamport, event }
    }
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
    entries: Vec<LogEntry>,         // full log, kept so peers can pull what they lack
    outbound: Option<broadcast::Sender<LogEntry>>, // push newly committed entries to peers
}

impl EventLog {
    fn open(path: PathBuf, origin: String) -> (Self, Vec<Event>) {
        let mut log = Self { path, origin, lamport: 0, versions: HashMap::new(), entries: Vec::new(), outbound: None };
        if let Ok(data) = std::fs::read_to_string(&log.path) {
            for line in data.lines().filter(|l| !l.trim().is_empty()) {
                match serde_json::from_str::<LogEntry>(line) {
                    Ok(entry) => {
                        log.absorb(&entry);
                        log.entries.push(entry);
                    }
                    Err(e) => tracing::warn!(%e, "skipping malformed event log line"),
                }
            }
        }
        let events = log.entries.iter().map(|e| e.event.clone()).collect();
        (log, events)
    }

    // Roll the clock and version vector forward over an entry. Local (channel)
    // entries carry no gossip identity, so they never touch the vector or clock.
    fn absorb(&mut self, entry: &LogEntry) {
        if entry.event.scope() != Scope::Global {
            return;
        }
        self.lamport = self.lamport.max(entry.lamport);
        self.versions.entry(entry.origin.clone()).and_modify(|s| *s = (*s).max(entry.seq)).or_insert(entry.seq);
    }

    // Seq the next locally-authored event will carry (0-based, per our origin).
    fn next_seq(&self) -> u64 {
        self.versions.get(&self.origin).map_or(0, |s| s + 1)
    }

    // Persist a locally-authored event. Global events get the next seq + a ticked
    // Lamport clock and are pushed to peers; local (channel) events are written
    // for restart but never gossiped and carry no version-vector identity.
    fn append(&mut self, event: Event) -> std::io::Result<()> {
        let global = event.scope() == Scope::Global;
        let entry = if global {
            self.lamport += 1;
            LogEntry { origin: self.origin.clone(), seq: self.next_seq(), lamport: self.lamport, event }
        } else {
            LogEntry { origin: self.origin.clone(), seq: 0, lamport: 0, event }
        };
        self.persist(&entry)?;
        if global {
            self.versions.insert(entry.origin.clone(), entry.seq);
            self.notify(&entry);
        }
        self.entries.push(entry);
        Ok(())
    }

    // Ingest an entry authored by another node — the gossip seam. Returns the
    // event to fold into state, or None if already applied (idempotent, so
    // re-delivery converges). Assumes per-origin in-order delivery.
    fn ingest(&mut self, entry: LogEntry) -> std::io::Result<Option<Event>> {
        // A node never accepts another node's channel state — only global (account)
        // identity replicates. This is the guarantee: you can't be handed ownership
        // of a channel that was registered on a network you're not part of.
        if entry.event.scope() != Scope::Global {
            return Ok(None);
        }
        if self.versions.get(&entry.origin).is_some_and(|&s| entry.seq <= s) {
            return Ok(None); // already have it
        }
        self.persist(&entry)?;
        self.lamport = self.lamport.max(entry.lamport) + 1; // Lamport receive rule
        self.versions.insert(entry.origin.clone(), entry.seq);
        let event = entry.event.clone();
        self.notify(&entry);
        self.entries.push(entry);
        Ok(Some(event))
    }

    // Push a freshly committed entry to connected peers, if any are wired up.
    // Best effort: a lagging subscriber just relies on the periodic digest.
    fn notify(&self, entry: &LogEntry) {
        if let Some(tx) = &self.outbound {
            let _ = tx.send(entry.clone());
        }
    }

    fn set_outbound(&mut self, tx: broadcast::Sender<LogEntry>) {
        self.outbound = Some(tx);
    }

    // Our version vector: highest seq applied per origin.
    fn version_vector(&self) -> HashMap<String, u64> {
        self.versions.clone()
    }

    // Global entries a peer is missing, given the version vector it advertised.
    // Local (channel) entries are never offered — they don't leave the node.
    fn missing_for(&self, peer: &HashMap<String, u64>) -> Vec<LogEntry> {
        self.entries
            .iter()
            .filter(|e| e.event.scope() == Scope::Global)
            .filter(|e| peer.get(&e.origin).map_or(true, |&s| e.seq > s))
            .cloned()
            .collect()
    }

    fn persist(&self, entry: &LogEntry) -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&self.path)?;
        writeln!(f, "{}", serde_json::to_string(entry).unwrap_or_default())
    }

    // How many entries the log currently holds.
    fn len(&self) -> usize {
        self.entries.len()
    }

    // Rewrite the log to a minimal snapshot: one event per live account and
    // channel, authored under our origin at fresh sequence numbers. Peers
    // re-converge because the register events overwrite and cert replay is
    // idempotent. The version vector resets to our origin; peers re-advertise
    // theirs on the next sync. Written to a temp file and renamed, so a crash
    // leaves the old log.
    fn compact(&mut self, events: Vec<Event>) -> std::io::Result<()> {
        let mut seq = self.next_seq();
        let mut last_global = None;
        let mut snapshot = Vec::with_capacity(events.len());
        for event in events {
            let entry = if event.scope() == Scope::Global {
                self.lamport += 1;
                let e = LogEntry { origin: self.origin.clone(), seq, lamport: self.lamport, event };
                last_global = Some(seq);
                seq += 1;
                e
            } else {
                LogEntry { origin: self.origin.clone(), seq: 0, lamport: 0, event }
            };
            snapshot.push(entry);
        }
        let tmp = self.path.with_extension("compact");
        {
            let mut f = std::fs::File::create(&tmp)?;
            for entry in &snapshot {
                writeln!(f, "{}", serde_json::to_string(entry).unwrap_or_default())?;
            }
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        self.versions = HashMap::new();
        if let Some(last) = last_global {
            self.versions.insert(self.origin.clone(), last);
        }
        self.entries = snapshot;
        Ok(())
    }
}

#[derive(Debug)]
pub enum RegError {
    Exists,
    Internal,
}

// What an ingested entry did to a locally-known account, so the engine can log
// out sessions that were relying on it.
pub enum AccountChange {
    TakenOver(String),
    Dropped(String),
}

#[derive(Debug)]
pub enum CertError {
    Invalid,    // not a plausible fingerprint
    InUse,      // already registered (to any account)
    NoAccount,  // target account does not exist
    Internal,   // persistence failed
}

#[derive(Debug)]
pub enum ChanError {
    Exists,     // channel already registered
    NoChannel,  // channel is not registered
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
    channels: HashMap<String, ChannelInfo>, // keyed by casefolded name
    grouped: HashMap<String, String>, // casefolded alias nick -> canonical account name
    log: EventLog,
    // PBKDF2 cost baked into new SCRAM verifiers; lowered by tests.
    pub(crate) scram_iterations: u32,
    // Whether outbound email is configured, so email features can gate themselves.
    email_enabled: bool,
    // Node-local, non-persisted password-reset codes: account -> (code, expiry).
    reset_codes: HashMap<String, (String, Instant)>,
}

fn key(name: &str) -> String {
    name.to_ascii_lowercase()
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

// Format a Unix timestamp (seconds) as "YYYY-MM-DD HH:MM:SS UTC", using Howard
// Hinnant's civil-from-days algorithm so no date crate is needed.
pub(crate) fn human_time(ts: u64) -> String {
    let days = (ts / 86400) as i64;
    let rem = ts % 86400;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02} {hh:02}:{mm:02}:{ss:02} UTC")
}

impl Db {
    pub fn open(path: impl Into<PathBuf>, origin: impl Into<String>) -> Self {
        let (log, events) = EventLog::open(path.into(), origin.into());
        let mut accounts = HashMap::new();
        let mut channels = HashMap::new();
        let mut grouped = HashMap::new();
        for event in events {
            apply(&mut accounts, &mut channels, &mut grouped, event);
        }
        tracing::info!(accounts = accounts.len(), channels = channels.len(), "account store loaded");
        Self { accounts, channels, grouped, log, scram_iterations: scram::DEFAULT_ITERATIONS, email_enabled: false, reset_codes: HashMap::new() }
    }

    /// Fold an entry authored by another node into the store — the services-side
    /// of the gossip seam. Idempotent (re-delivered entries are dropped). Returns
    /// the account name if this ingest changed its owner (a registration conflict
    /// resolved against the local claim), so the caller can log out stale sessions.
    pub fn ingest(&mut self, entry: LogEntry) -> std::io::Result<Option<AccountChange>> {
        // Snapshot the incoming account's local owner before applying, to detect a
        // takeover (home changed) or a remote drop (it disappears).
        let watched: Option<(String, Option<String>)> = match &entry.event {
            Event::AccountRegistered(a) => Some((a.name.clone(), self.account(&a.name).map(|c| c.home.clone()))),
            Event::AccountDropped { account } => Some((account.clone(), self.account(account).map(|c| c.home.clone()))),
            _ => None,
        };
        if let Some(event) = self.log.ingest(entry)? {
            apply(&mut self.accounts, &mut self.channels, &mut self.grouped, event);
        }
        if let Some((name, prev_home)) = watched {
            match (prev_home, self.account(&name).map(|c| c.home.clone())) {
                (Some(prev), Some(cur)) if cur != prev => return Ok(Some(AccountChange::TakenOver(name))),
                (Some(_), None) => return Ok(Some(AccountChange::Dropped(name))),
                _ => {}
            }
        }
        Ok(None)
    }

    /// Rewrite the log to one entry per account and channel, reclaiming churn.
    pub fn compact(&mut self) -> std::io::Result<()> {
        let before = self.log.len();
        let mut snapshot: Vec<Event> = self.accounts.values().cloned().map(Event::AccountRegistered).collect();
        for c in self.channels.values() {
            snapshot.push(Event::ChannelRegistered { name: c.name.clone(), founder: c.founder.clone(), ts: c.ts });
            if !c.lock_on.is_empty() || !c.lock_off.is_empty() {
                snapshot.push(Event::ChannelMlock { name: c.name.clone(), on: c.lock_on.clone(), off: c.lock_off.clone() });
            }
            for a in &c.access {
                snapshot.push(Event::ChannelAccessAdd { channel: c.name.clone(), account: a.account.clone(), level: a.level.clone() });
            }
            for k in &c.akick {
                snapshot.push(Event::ChannelAkickAdd { channel: c.name.clone(), mask: k.mask.clone(), reason: k.reason.clone() });
            }
            if !c.desc.is_empty() {
                snapshot.push(Event::ChannelDescSet { channel: c.name.clone(), desc: c.desc.clone() });
            }
            if !c.entrymsg.is_empty() {
                snapshot.push(Event::ChannelEntryMsgSet { channel: c.name.clone(), msg: c.entrymsg.clone() });
            }
        }
        for (nick, account) in &self.grouped {
            snapshot.push(Event::NickGrouped { nick: nick.clone(), account: account.clone() });
        }
        self.log.compact(snapshot)?;
        tracing::info!(before, after = self.log.len(), "compacted event log");
        Ok(())
    }

    /// Whether the log has grown enough past the live state to be worth compacting.
    pub fn should_compact(&self) -> bool {
        self.log.len() > (self.accounts.len() + self.channels.len()) * 3 + 64
    }

    /// Wire the log to a broadcast channel; each new entry is pushed to peers.
    pub fn set_outbound(&mut self, tx: broadcast::Sender<LogEntry>) {
        self.log.set_outbound(tx);
    }

    /// Our version vector, advertised to peers so they can send what we lack.
    pub fn version_vector(&self) -> HashMap<String, u64> {
        self.log.version_vector()
    }

    /// The log entries a peer is missing, given the version vector it sent.
    pub fn missing_for(&self, peer: &HashMap<String, u64>) -> Vec<LogEntry> {
        self.log.missing_for(peer)
    }

    pub fn exists(&self, name: &str) -> bool {
        self.resolved_key(name).is_some()
    }

    // Resolve a name (a registered account, or a nick grouped to one) to the
    // owning account's storage key.
    fn resolved_key(&self, name: &str) -> Option<String> {
        let k = key(name);
        if self.accounts.contains_key(&k) {
            return Some(k);
        }
        self.grouped.get(&k).map(|acct| key(acct))
    }

    /// The canonical account name for `name`, whether it is the account itself or
    /// a nick grouped to it.
    pub fn resolve_account(&self, name: &str) -> Option<&str> {
        let k = self.resolved_key(name)?;
        self.accounts.get(&k).map(|a| a.name.as_str())
    }

    /// Group alias `nick` to an existing `account`.
    pub fn group_nick(&mut self, nick: &str, account: &str) -> Result<(), RegError> {
        if !self.accounts.contains_key(&key(account)) {
            return Err(RegError::Internal);
        }
        self.log.append(Event::NickGrouped { nick: nick.to_string(), account: account.to_string() }).map_err(|_| RegError::Internal)?;
        self.grouped.insert(key(nick), account.to_string());
        Ok(())
    }

    /// Remove grouped alias `nick`. Ok(false) if it wasn't grouped.
    pub fn ungroup_nick(&mut self, nick: &str) -> Result<bool, RegError> {
        if !self.grouped.contains_key(&key(nick)) {
            return Ok(false);
        }
        self.log.append(Event::NickUngrouped { nick: nick.to_string() }).map_err(|_| RegError::Internal)?;
        self.grouped.remove(&key(nick));
        Ok(true)
    }

    /// The alias nicks grouped to `account` (not the account name itself).
    pub fn grouped_nicks(&self, account: &str) -> Vec<String> {
        self.grouped.iter().filter(|(_, a)| a.eq_ignore_ascii_case(account)).map(|(nick, _)| nick.clone()).collect()
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
            home: self.log.origin.clone(),
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

    #[cfg(test)]
    pub(crate) fn test_hash(&self, name: &str) -> Option<String> {
        self.accounts.get(&key(name)).map(|a| a.password_hash.clone())
    }

    /// Check credentials; on success return the account's canonical name (its
    /// stored casing), else None.
    pub fn authenticate(&self, name: &str, password: &str) -> Option<&str> {
        let account = self.accounts.get(&self.resolved_key(name)?)?;
        verify_password(password, &account.password_hash).then_some(account.name.as_str())
    }

    /// The account's canonical name and its SCRAM verifier for `mech`, if any.
    pub fn scram_lookup(&self, name: &str, mech: &str) -> Option<(&str, &str)> {
        let account = self.accounts.get(&self.resolved_key(name)?)?;
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

    /// Whether outbound email is configured.
    pub fn email_enabled(&self) -> bool {
        self.email_enabled
    }

    pub fn set_email_enabled(&mut self, on: bool) {
        self.email_enabled = on;
    }

    /// Issue a fresh password-reset code for `account`, valid for 15 minutes.
    pub fn issue_reset_code(&mut self, account: &str) -> String {
        let code = gen_code();
        self.reset_codes.insert(key(account), (code.clone(), Instant::now() + Duration::from_secs(900)));
        code
    }

    /// Consume a reset code for `account`: true if it matches and hasn't expired.
    pub fn take_reset_code(&mut self, account: &str, code: &str) -> bool {
        let k = key(account);
        match self.reset_codes.get(&k) {
            Some((c, deadline)) if c == code && *deadline > Instant::now() => {
                self.reset_codes.remove(&k);
                true
            }
            _ => false,
        }
    }

    /// Set (or clear) `account`'s email.
    pub fn set_email(&mut self, account: &str, email: Option<String>) -> Result<(), RegError> {
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return Err(RegError::Internal);
        }
        self.log.append(Event::AccountEmailSet { account: account.to_string(), email: email.clone() }).map_err(|_| RegError::Internal)?;
        self.accounts.get_mut(&k).unwrap().email = email;
        Ok(())
    }

    /// Replace `account`'s password with freshly derived credentials.
    pub fn set_credentials(&mut self, account: &str, creds: Credentials) -> Result<(), RegError> {
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return Err(RegError::Internal);
        }
        self.log
            .append(Event::AccountPasswordSet {
                account: account.to_string(),
                password_hash: creds.password_hash.clone(),
                scram256: creds.scram256.clone(),
                scram512: creds.scram512.clone(),
            })
            .map_err(|_| RegError::Internal)?;
        let a = self.accounts.get_mut(&k).unwrap();
        a.password_hash = creds.password_hash;
        a.scram256 = Some(creds.scram256);
        a.scram512 = Some(creds.scram512);
        Ok(())
    }

    /// Delete `account`. Ok(false) if it wasn't registered.
    pub fn drop_account(&mut self, account: &str) -> Result<bool, RegError> {
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return Ok(false);
        }
        self.log.append(Event::AccountDropped { account: account.to_string() }).map_err(|_| RegError::Internal)?;
        self.accounts.remove(&k);
        Ok(true)
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

    /// Register `name` to `founder` (an account name).
    pub fn register_channel(&mut self, name: &str, founder: &str) -> Result<(), ChanError> {
        let k = key(name);
        if self.channels.contains_key(&k) {
            return Err(ChanError::Exists);
        }
        let ts = now();
        self.log
            .append(Event::ChannelRegistered { name: name.to_string(), founder: founder.to_string(), ts })
            .map_err(|_| ChanError::Internal)?;
        self.channels.insert(k, ChannelInfo { name: name.to_string(), founder: founder.to_string(), ts, lock_on: String::new(), lock_off: String::new(), access: Vec::new(), akick: Vec::new(), desc: String::new(), entrymsg: String::new() });
        Ok(())
    }

    /// The registration for `name`, if any.
    pub fn channel(&self, name: &str) -> Option<&ChannelInfo> {
        self.channels.get(&key(name))
    }

    /// The account record for `name` (its canonical casing), if registered.
    pub fn account(&self, name: &str) -> Option<&Account> {
        self.accounts.get(&key(name))
    }

    /// All registered channels, for listing.
    pub fn channels(&self) -> impl Iterator<Item = &ChannelInfo> {
        self.channels.values()
    }

    /// Names of channels founded by `account` (case-insensitive).
    pub fn channels_owned_by(&self, account: &str) -> Vec<String> {
        self.channels
            .values()
            .filter(|c| c.founder.eq_ignore_ascii_case(account))
            .map(|c| c.name.clone())
            .collect()
    }

    /// Set the mode-lock (chars to keep set / unset) for a registered channel.
    pub fn set_mlock(&mut self, name: &str, on: &str, off: &str) -> Result<(), ChanError> {
        let k = key(name);
        if !self.channels.contains_key(&k) {
            return Err(ChanError::NoChannel);
        }
        self.log
            .append(Event::ChannelMlock { name: name.to_string(), on: on.to_string(), off: off.to_string() })
            .map_err(|_| ChanError::Internal)?;
        let c = self.channels.get_mut(&k).unwrap();
        c.lock_on = on.to_string();
        c.lock_off = off.to_string();
        Ok(())
    }

    /// Grant `account` a level ("op"/"voice") on `channel`.
    pub fn access_add(&mut self, channel: &str, account: &str, level: &str) -> Result<(), ChanError> {
        let k = key(channel);
        if !self.channels.contains_key(&k) {
            return Err(ChanError::NoChannel);
        }
        self.log
            .append(Event::ChannelAccessAdd { channel: channel.to_string(), account: account.to_string(), level: level.to_string() })
            .map_err(|_| ChanError::Internal)?;
        let c = self.channels.get_mut(&k).unwrap();
        c.access.retain(|a| !a.account.eq_ignore_ascii_case(account));
        c.access.push(ChanAccess { account: account.to_string(), level: level.to_string() });
        Ok(())
    }

    /// Remove `account` from `channel`'s access list. Ok(false) if not present.
    pub fn access_del(&mut self, channel: &str, account: &str) -> Result<bool, ChanError> {
        let k = key(channel);
        let Some(c) = self.channels.get(&k) else {
            return Err(ChanError::NoChannel);
        };
        if !c.access.iter().any(|a| a.account.eq_ignore_ascii_case(account)) {
            return Ok(false);
        }
        self.log
            .append(Event::ChannelAccessDel { channel: channel.to_string(), account: account.to_string() })
            .map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().access.retain(|a| !a.account.eq_ignore_ascii_case(account));
        Ok(true)
    }

    /// Add an auto-kick `mask` (with `reason`) to `channel`.
    pub fn akick_add(&mut self, channel: &str, mask: &str, reason: &str) -> Result<(), ChanError> {
        let k = key(channel);
        if !self.channels.contains_key(&k) {
            return Err(ChanError::NoChannel);
        }
        self.log
            .append(Event::ChannelAkickAdd { channel: channel.to_string(), mask: mask.to_string(), reason: reason.to_string() })
            .map_err(|_| ChanError::Internal)?;
        let c = self.channels.get_mut(&k).unwrap();
        c.akick.retain(|a| !a.mask.eq_ignore_ascii_case(mask));
        c.akick.push(ChanAkick { mask: mask.to_string(), reason: reason.to_string() });
        Ok(())
    }

    /// Remove auto-kick `mask` from `channel`. Ok(false) if not present.
    pub fn akick_del(&mut self, channel: &str, mask: &str) -> Result<bool, ChanError> {
        let k = key(channel);
        let Some(c) = self.channels.get(&k) else {
            return Err(ChanError::NoChannel);
        };
        if !c.akick.iter().any(|a| a.mask.eq_ignore_ascii_case(mask)) {
            return Ok(false);
        }
        self.log
            .append(Event::ChannelAkickDel { channel: channel.to_string(), mask: mask.to_string() })
            .map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().akick.retain(|a| !a.mask.eq_ignore_ascii_case(mask));
        Ok(true)
    }

    /// Transfer `channel`'s founder to `account`.
    pub fn set_founder(&mut self, channel: &str, account: &str) -> Result<(), ChanError> {
        let k = key(channel);
        if !self.channels.contains_key(&k) {
            return Err(ChanError::NoChannel);
        }
        self.log
            .append(Event::ChannelFounderSet { channel: channel.to_string(), founder: account.to_string() })
            .map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().founder = account.to_string();
        Ok(())
    }

    /// Set `channel`'s description (empty clears it).
    pub fn set_desc(&mut self, channel: &str, desc: &str) -> Result<(), ChanError> {
        let k = key(channel);
        if !self.channels.contains_key(&k) {
            return Err(ChanError::NoChannel);
        }
        self.log
            .append(Event::ChannelDescSet { channel: channel.to_string(), desc: desc.to_string() })
            .map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().desc = desc.to_string();
        Ok(())
    }

    /// Set `channel`'s entry message (empty clears it).
    pub fn set_entrymsg(&mut self, channel: &str, msg: &str) -> Result<(), ChanError> {
        let k = key(channel);
        if !self.channels.contains_key(&k) {
            return Err(ChanError::NoChannel);
        }
        self.log
            .append(Event::ChannelEntryMsgSet { channel: channel.to_string(), msg: msg.to_string() })
            .map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().entrymsg = msg.to_string();
        Ok(())
    }

    /// Unregister `name`.
    pub fn drop_channel(&mut self, name: &str) -> Result<(), ChanError> {
        let k = key(name);
        if !self.channels.contains_key(&k) {
            return Err(ChanError::NoChannel);
        }
        self.log.append(Event::ChannelDropped { name: name.to_string() }).map_err(|_| ChanError::Internal)?;
        self.channels.remove(&k);
        Ok(())
    }
}

// Whether `held` is the rightful owner over a rival `claim` to the same name:
// the earlier registration wins (lower ts), ties broken by the lower origin. A
// total order over the fields carried in the account, so it survives compaction
// (which re-authors the log envelope but keeps account content) and is identical
// on every node. Strictly less-than, so an equal (idempotent) re-delivery still
// overwrites with identical content.
fn owns_over(held: &Account, claim: &Account) -> bool {
    (held.ts, held.home.as_str()) < (claim.ts, claim.home.as_str())
}

// Fold one event into the store. Shared by log replay (`open`) and gossip
// ingest, so both routes reconstruct identical state.
fn apply(accounts: &mut HashMap<String, Account>, channels: &mut HashMap<String, ChannelInfo>, grouped: &mut HashMap<String, String>, event: Event) {
    match event {
        Event::AccountRegistered(a) => {
            // Resolve a concurrent registration of the same name deterministically:
            // keep whichever claim is earlier (lower ts, then lower origin), so every
            // node converges on the same owner regardless of gossip delivery order.
            let k = key(&a.name);
            let keep_existing = accounts.get(&k).is_some_and(|cur| owns_over(cur, &a));
            if !keep_existing {
                accounts.insert(k, a);
            }
        }
        Event::CertAdded { account, fp } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                if !a.certfps.contains(&fp) {
                    a.certfps.push(fp); // idempotent: safe to replay over a snapshot
                }
            }
        }
        Event::CertRemoved { account, fp } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                a.certfps.retain(|c| *c != fp);
            }
        }
        Event::AccountEmailSet { account, email } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                a.email = email;
            }
        }
        Event::AccountPasswordSet { account, password_hash, scram256, scram512 } => {
            if let Some(a) = accounts.get_mut(&key(&account)) {
                a.password_hash = password_hash;
                a.scram256 = Some(scram256);
                a.scram512 = Some(scram512);
            }
        }
        Event::AccountDropped { account } => {
            accounts.remove(&key(&account));
            grouped.retain(|_, a| !a.eq_ignore_ascii_case(&account)); // its aliases go too
        }
        Event::NickGrouped { nick, account } => {
            grouped.insert(key(&nick), account);
        }
        Event::NickUngrouped { nick } => {
            grouped.remove(&key(&nick));
        }
        Event::ChannelRegistered { name, founder, ts } => {
            channels.insert(key(&name), ChannelInfo { name, founder, ts, lock_on: String::new(), lock_off: String::new(), access: Vec::new(), akick: Vec::new(), desc: String::new(), entrymsg: String::new() });
        }
        Event::ChannelDropped { name } => {
            channels.remove(&key(&name));
        }
        Event::ChannelMlock { name, on, off } => {
            if let Some(c) = channels.get_mut(&key(&name)) {
                c.lock_on = on;
                c.lock_off = off;
            }
        }
        Event::ChannelAccessAdd { channel, account, level } => {
            if let Some(c) = channels.get_mut(&key(&channel)) {
                c.access.retain(|a| !a.account.eq_ignore_ascii_case(&account));
                c.access.push(ChanAccess { account, level });
            }
        }
        Event::ChannelAccessDel { channel, account } => {
            if let Some(c) = channels.get_mut(&key(&channel)) {
                c.access.retain(|a| !a.account.eq_ignore_ascii_case(&account));
            }
        }
        Event::ChannelAkickAdd { channel, mask, reason } => {
            if let Some(c) = channels.get_mut(&key(&channel)) {
                c.akick.retain(|k| !k.mask.eq_ignore_ascii_case(&mask));
                c.akick.push(ChanAkick { mask, reason });
            }
        }
        Event::ChannelAkickDel { channel, mask } => {
            if let Some(c) = channels.get_mut(&key(&channel)) {
                c.akick.retain(|k| !k.mask.eq_ignore_ascii_case(&mask));
            }
        }
        Event::ChannelFounderSet { channel, founder } => {
            if let Some(c) = channels.get_mut(&key(&channel)) {
                c.founder = founder;
            }
        }
        Event::ChannelDescSet { channel, desc } => {
            if let Some(c) = channels.get_mut(&key(&channel)) {
                c.desc = desc;
            }
        }
        Event::ChannelEntryMsgSet { channel, msg } => {
            if let Some(c) = channels.get_mut(&key(&channel)) {
                c.entrymsg = msg;
            }
        }
    }
}

// Case-insensitive glob match supporting `*` (any run) and `?` (one char),
// used for auto-kick hostmasks. Iterative with backtracking, no allocation.
fn glob_match(pattern: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (
        pattern.chars().flat_map(char::to_lowercase).collect(),
        text.chars().flat_map(char::to_lowercase).collect(),
    );
    let (mut pi, mut ti) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

// A random 6-digit code for email verification / password reset.
fn gen_code() -> String {
    let mut b = [0u8; 4];
    OsRng.fill_bytes(&mut b);
    format!("{:06}", u32::from_le_bytes(b) % 1_000_000)
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

    #[test]
    fn formats_unix_time_as_utc() {
        assert_eq!(human_time(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(human_time(1783844590), "2026-07-12 08:23:10 UTC");
    }

    #[test]
    fn glob_matches_hostmasks() {
        assert!(glob_match("*!*@host.example", "bob!~b@host.example"));
        assert!(glob_match("bob!*@*", "BOB!~b@1.2.3.4"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("nick?!*@*", "nickX!~x@h"));
        assert!(!glob_match("*!*@host.example", "bob!~b@other"));
        assert!(!glob_match("alice!*@*", "bob!~b@h"));
    }

    #[test]
    fn account_conflict_resolves_deterministically() {
        let alice = |hash: &str, ts: u64, home: &str| Account {
            name: "alice".into(), password_hash: hash.into(), email: None,
            ts, home: home.into(), scram256: None, scram512: None, certfps: vec![],
        };
        let converge = |first: &Account, second: &Account| {
            let (mut acc, mut ch, mut gr) = (HashMap::new(), HashMap::new(), HashMap::new());
            apply(&mut acc, &mut ch, &mut gr, Event::AccountRegistered(first.clone()));
            apply(&mut acc, &mut ch, &mut gr, Event::AccountRegistered(second.clone()));
            acc["alice"].password_hash.clone()
        };
        // Earlier registration wins, regardless of which claim applies first.
        let early = alice("EARLY", 100, "nodeB");
        let late = alice("LATE", 200, "nodeA");
        assert_eq!(converge(&early, &late), "EARLY");
        assert_eq!(converge(&late, &early), "EARLY", "commutative: same winner in either order");
        // Same ts: the lower origin wins, in either order.
        let a = alice("A", 100, "nodeA");
        let b = alice("B", 100, "nodeB");
        assert_eq!(converge(&a, &b), "A");
        assert_eq!(converge(&b, &a), "A", "ts tie broken by lower origin, either order");
        // Idempotent: re-delivering the winner keeps it.
        assert_eq!(converge(&a, &a), "A");
    }

    #[test]
    fn channel_state_is_node_local_but_persists() {
        let path = tmp("scope");
        {
            let mut db = Db::open(&path, "N1");
            db.register("alice", "pw", None).unwrap(); // global
            db.register_channel("#c", "alice").unwrap(); // local
            db.set_mlock("#c", "nt", "").unwrap(); // local
            // Only the account advances the version vector.
            assert_eq!(db.version_vector().get("N1"), Some(&0), "channels don't advance the vector");
            // A fresh peer is offered the account, never the channel.
            let missing = db.missing_for(&HashMap::new());
            assert_eq!(missing.len(), 1, "only the global account entry is offered: {missing:?}");
            assert!(matches!(missing[0].event, Event::AccountRegistered(_)));
        }
        // Reopen: node-local channel state replays from disk unchanged.
        let db = Db::open(&path, "N1");
        assert!(db.exists("alice"));
        assert_eq!(db.channel("#c").map(|c| c.lock_on.clone()), Some("nt".to_string()), "channel state persists locally");
        assert_eq!(db.version_vector().get("N1"), Some(&0), "vector unchanged after replay");
    }

    #[test]
    fn akick_add_del_and_match() {
        let mut db = Db::open(&tmp("akick"), "N1");
        db.register_channel("#c", "founder").unwrap();
        db.akick_add("#c", "*!*@bad.host", "spam").unwrap();
        let info = db.channel("#c").unwrap();
        assert!(info.akick_match("evil!~e@bad.host").is_some());
        assert!(info.akick_match("good!~g@ok.host").is_none());
        assert!(db.akick_del("#c", "*!*@bad.host").unwrap());
        assert!(!db.akick_del("#c", "*!*@bad.host").unwrap());
        assert!(db.channel("#c").unwrap().akick.is_empty());
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
            ts: 0, home: "peer".into(), scram256: None, scram512: None, certfps: vec![],
        };
        let entry = LogEntry { origin: "peer".into(), seq: 0, lamport: 1, event: Event::AccountRegistered(bob) };
        db.ingest(entry).unwrap();
        assert!(db.exists("bob"), "peer's account is present locally");
        assert!(db.exists("alice"), "local account still there");
    }

    // Compaction collapses churn to one entry per account and survives a reload.
    #[test]
    fn compact_preserves_state_and_shrinks() {
        let p = tmp("compact");
        let mut db = Db::open(&p, "local");
        db.scram_iterations = 4096;
        db.register("alice", "pw", None).unwrap();
        db.register("bob", "pw", None).unwrap();
        for i in 0..10u32 {
            let fp = format!("{i:032x}");
            db.certfp_add("alice", &fp).unwrap();
            db.certfp_del("alice", &fp).unwrap();
        }
        let kept = "bb".repeat(16);
        db.certfp_add("bob", &kept).unwrap();

        let before = db.log.len();
        db.compact().unwrap();
        assert!(db.log.len() < before, "log shrank: {before} -> {}", db.log.len());
        assert_eq!(db.log.len(), 2, "one entry per account");

        drop(db);
        let db = Db::open(&p, "local");
        assert!(db.authenticate("alice", "pw").is_some(), "password survives compaction");
        assert!(db.certfps("alice").is_empty(), "churned certs are gone");
        assert_eq!(db.certfps("bob"), &[kept][..], "kept cert survives");
    }

    // A peer with an empty log converges from a node that has already compacted.
    #[test]
    fn compacted_node_still_converges() {
        let mut a = Db::open(tmp("compA"), "A");
        a.scram_iterations = 4096;
        a.register("alice", "pw", None).unwrap();
        let fp = "cc".repeat(16);
        a.certfp_add("alice", &fp).unwrap();
        a.compact().unwrap();

        let mut b = Db::open(tmp("compB"), "B");
        b.scram_iterations = 4096;
        for entry in a.missing_for(&b.version_vector()) {
            b.ingest(entry).unwrap();
        }
        assert!(b.exists("alice"), "B converges from a compacted node");
        assert_eq!(b.certfps("alice"), &[fp][..], "certs arrive folded into the snapshot");
    }

    // Channels register (case-insensitively unique), persist, and drop.
    #[test]
    fn channels_register_drop_and_persist() {
        let p = tmp("chan");
        let mut db = Db::open(&p, "local");
        db.register_channel("#Chat", "alice").unwrap();
        assert!(matches!(db.register_channel("#chat", "bob"), Err(ChanError::Exists)), "dup is case-insensitive");
        assert_eq!(db.channel("#CHAT").map(|c| c.founder.as_str()), Some("alice"));

        drop(db);
        let mut db = Db::open(&p, "local");
        assert_eq!(db.channel("#chat").map(|c| c.founder.as_str()), Some("alice"), "survives reopen");
        db.drop_channel("#chat").unwrap();
        assert!(db.channel("#chat").is_none());
        assert!(matches!(db.drop_channel("#chat"), Err(ChanError::NoChannel)));
    }

    // Mode lock persists, renders the applied string, and detects violations.
    #[test]
    fn mode_lock_persists_and_enforces() {
        let p = tmp("mlock");
        let mut db = Db::open(&p, "local");
        db.register_channel("#chan", "alice").unwrap();
        db.set_mlock("#chan", "nt", "s").unwrap();

        let info = db.channel("#chan").unwrap();
        assert_eq!(info.lock_modes(), "+rnt-s");
        assert_eq!(info.enforce("-nt"), Some("+nt".to_string())); // locked-on removed
        assert_eq!(info.enforce("+s"), Some("-s".to_string()));   // locked-off added
        assert_eq!(info.enforce("-r"), Some("+r".to_string()));   // +r always locked
        assert_eq!(info.enforce("+m"), None);                     // unrelated mode ignored

        drop(db);
        let db = Db::open(&p, "local");
        assert_eq!(db.channel("#chan").unwrap().lock_modes(), "+rnt-s", "survives reopen");
    }

    // Access list drives join modes, is case-insensitive, and persists.
    #[test]
    fn access_list_grants_join_modes() {
        let p = tmp("access");
        let mut db = Db::open(&p, "local");
        db.register_channel("#c", "boss").unwrap();
        db.access_add("#c", "alice", "op").unwrap();
        db.access_add("#c", "bob", "voice").unwrap();

        let info = db.channel("#c").unwrap();
        assert_eq!(info.join_mode("boss"), Some("+o"));  // founder
        assert_eq!(info.join_mode("ALICE"), Some("+o")); // op, case-insensitive
        assert_eq!(info.join_mode("bob"), Some("+v"));   // voice
        assert_eq!(info.join_mode("nobody"), None);

        assert!(db.access_del("#c", "alice").unwrap());
        assert!(!db.access_del("#c", "alice").unwrap());

        drop(db);
        let db = Db::open(&p, "local");
        assert_eq!(db.channel("#c").unwrap().join_mode("bob"), Some("+v"), "survives reopen");
        assert_eq!(db.channel("#c").unwrap().join_mode("alice"), None, "removal survives reopen");
    }
}
