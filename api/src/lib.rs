//! The module SDK. A service or protocol module depends only on this crate:
//! it carries the traits a module implements and the normalized vocabulary the
//! engine speaks, with no storage or runtime dependencies of its own.

// Branded account emails (confirm / reset), shared by the engine and modules.
pub mod email;

// ---------------------------------------------------------------------------
// Protocol vocabulary
// ---------------------------------------------------------------------------

// Normalized inbound facts, translated from the uplink's raw lines.
#[derive(Debug, Clone)]
pub enum NetEvent {
    Registered,
    EndBurst,
    Ping { token: String, from: Option<String> },
    Privmsg { from: String, to: String, text: String },
    UserConnect { uid: String, nick: String, host: String },
    NickChange { uid: String, nick: String },
    // A channel was created or bursted (an FJOIN). Subsequent single joins arrive
    // as IJOIN and are not surfaced.
    ChannelCreate { channel: String },
    // A user joined a channel (an FJOIN member or an IJOIN), for auto-op. `op` is
    // whether they hold channel-operator status at that point (an FJOIN prefix).
    Join { uid: String, channel: String, op: bool },
    // A user left a channel (PART) or was removed (KICK), for membership tracking.
    Part { uid: String, channel: String },
    // A user's channel-operator status changed (FMODE +o/-o), for live op tracking.
    ChannelOp { channel: String, uid: String, op: bool },
    // A channel's modes changed (FMODE), for enforcing mode locks. Our own
    // changes are filtered out by the protocol layer.
    ChannelModeChange { channel: String, modes: String },
    // A channel's key (+k/-k) changed, tracked so GETKEY can report it.
    ChannelKey { channel: String, key: Option<String> },
    Quit { uid: String },
    // An ircd relaying an IRCv3 account-registration request to us as the authority.
    AccountRequest { reqid: String, origin: String, kind: String, account: String, p2: String, p3: String },
    // An ircd relaying a SASL exchange step to us (the SASL agent). mode = H/S/C/D.
    Sasl { client: String, agent: String, mode: String, data: Vec<String> },
    Unknown { line: String },
}

// Normalized outbound intents the engine wants performed on the network.
#[derive(Debug, Clone)]
pub enum NetAction {
    Burst,
    EndBurst,
    Pong { token: String, from: Option<String> },
    IntroduceUser { uid: String, nick: String, ident: String, host: String, gecos: String },
    Privmsg { from: String, to: String, text: String },
    Notice { from: String, to: String, text: String },
    AccountResponse { reqid: String, kind: String, account: String, status: String, code: String, message: String },
    // A SASL exchange step back to the ircd, sourced from our SASL agent. mode = C/D.
    Sasl { agent: String, client: String, mode: String, data: Vec<String> },
    // Publish network state to the uplink: target "*" is server-global (e.g. the
    // advertised SASL mechanism list), otherwise a user uid (e.g. their account).
    Metadata { target: String, key: String, value: String },
    // Force a user's nick (SVSNICK), e.g. renaming to a guest nick on logout.
    // The protocol stamps the new nick's timestamp.
    ForceNick { uid: String, nick: String },
    // Set channel modes from services, e.g. +r on a registered channel. `from` is
    // the pseudoclient uid to source it from (empty = the services server). The
    // protocol stamps a timestamp the ircd will accept.
    ChannelMode { from: String, channel: String, modes: String },
    // Kick a user from a channel, sourced from pseudoclient `from`.
    Kick { from: String, channel: String, uid: String, reason: String },
    // Set a channel's topic, sourced from pseudoclient `from`.
    Topic { from: String, channel: String, topic: String },
    // Invite a user to a channel, sourced from pseudoclient `from`.
    Invite { from: String, uid: String, channel: String },
    Raw(String),
    // Internal only, never serialized to the wire: a registration whose password
    // still needs its (expensive) key derivation. The link layer runs the
    // derivation off-thread, then calls Engine::complete_register.
    DeferRegister { account: String, password: String, email: Option<String>, reply: RegReply },
    // Internal only: a password change awaiting the same off-thread derivation.
    // The link layer derives, then calls Engine::complete_password_change.
    DeferPassword { account: String, password: String, agent: String, uid: String },
    // Internal only: send an email (plaintext + optional HTML). The link layer
    // pipes it to the configured mail command off-thread; never serialized.
    SendEmail { to: String, subject: String, text: String, html: Option<String> },
}

// How to answer a registration once its credentials have been derived.
#[derive(Debug, Clone)]
pub enum RegReply {
    // IRCv3 account-registration relay: answer the requesting ircd.
    Relay { reqid: String, kind: String },
    // NickServ REGISTER: NOTICE the requesting user, logging them in on success.
    NickServ { agent: String, uid: String, nick: String },
}

// The ircd link layer. The engine only ever sees NetEvent / NetAction; raw
// server-to-server lines live entirely behind a Protocol impl, so a new ircd is
// one new module and the engine is untouched.
pub trait Protocol: Send {
    /// Lines to send immediately on connect (auth / capability negotiation).
    fn handshake(&mut self) -> Vec<String>;
    /// One raw inbound line -> zero or more normalized events.
    fn parse(&mut self, line: &str) -> Vec<NetEvent>;
    /// One normalized action -> the raw line(s) that realise it.
    fn serialize(&mut self, action: &NetAction) -> Vec<String>;
    /// Our own server id, used as the source prefix for server-sourced lines.
    fn sid(&self) -> &str;
}

// ---------------------------------------------------------------------------
// Service vocabulary
// ---------------------------------------------------------------------------

// Who sent the command, resolved by the engine (UID + current nick + the
// account they are identified to, if any).
pub struct Sender<'a> {
    pub uid: &'a str,
    pub nick: &'a str,
    pub account: Option<&'a str>,
}

// The intent sink a service writes to. A service never mutates the network or
// the store itself; it pushes normalized actions the engine drains and applies.
#[derive(Default)]
pub struct ServiceCtx {
    pub actions: Vec<NetAction>,
}

impl ServiceCtx {
    pub fn notice(&mut self, from: &str, to: &str, text: impl Into<String>) {
        self.actions.push(NetAction::Notice {
            from: from.to_string(),
            to: to.to_string(),
            text: text.into(),
        });
    }

    // Hand a registration to the engine to finish: its password derivation runs
    // off the reactor, then the engine commits it and answers `reply`.
    pub fn defer_register(&mut self, account: impl Into<String>, password: impl Into<String>, email: Option<String>, reply: RegReply) {
        self.actions.push(NetAction::DeferRegister {
            account: account.into(),
            password: password.into(),
            email,
            reply,
        });
    }

    // Send an email (the link layer pipes it to the configured mail command).
    pub fn send_email(&mut self, to: impl Into<String>, subject: impl Into<String>, text: impl Into<String>, html: Option<String>) {
        self.actions.push(NetAction::SendEmail { to: to.into(), subject: subject.into(), text: text.into(), html });
    }

    // Hand a password change to the engine to finish: its derivation runs off the
    // reactor, then the engine commits it and notices `uid`, sourced from `agent`.
    pub fn defer_password(&mut self, account: impl Into<String>, password: impl Into<String>, agent: impl Into<String>, uid: impl Into<String>) {
        self.actions.push(NetAction::DeferPassword {
            account: account.into(),
            password: password.into(),
            agent: agent.into(),
            uid: uid.into(),
        });
    }

    // Log a user into an account: sets the accountname the ircd turns into
    // RPL_LOGGEDIN (900) and exposes to account-tag / WHOX, the same login the
    // SASL agent applies. Used after a successful REGISTER / IDENTIFY.
    pub fn login(&mut self, uid: &str, account: &str) {
        self.actions.push(NetAction::Metadata {
            target: uid.to_string(),
            key: "accountname".to_string(),
            value: account.to_string(),
        });
    }

    // Log a user out: clearing the accountname the ircd turns into RPL_LOGGEDOUT
    // (901) and drops from account-tag / WHOX. The inverse of `login`.
    pub fn logout(&mut self, uid: &str) {
        self.actions.push(NetAction::Metadata {
            target: uid.to_string(),
            key: "accountname".to_string(),
            value: String::new(),
        });
    }

    // Force a user's nick (SVSNICK), e.g. to a guest nick after logout.
    pub fn force_nick(&mut self, uid: &str, nick: &str) {
        self.actions.push(NetAction::ForceNick {
            uid: uid.to_string(),
            nick: nick.to_string(),
        });
    }

    // Set channel modes, sourced from pseudoclient `from` (e.g. ChanServ).
    pub fn channel_mode(&mut self, from: &str, channel: &str, modes: &str) {
        self.actions.push(NetAction::ChannelMode {
            from: from.to_string(),
            channel: channel.to_string(),
            modes: modes.to_string(),
        });
    }

    // Kick a user, sourced from pseudoclient `from`.
    pub fn kick(&mut self, from: &str, channel: &str, uid: &str, reason: &str) {
        self.actions.push(NetAction::Kick {
            from: from.to_string(),
            channel: channel.to_string(),
            uid: uid.to_string(),
            reason: reason.to_string(),
        });
    }

    // Set a channel's topic, sourced from pseudoclient `from`.
    pub fn topic(&mut self, from: &str, channel: &str, topic: &str) {
        self.actions.push(NetAction::Topic {
            from: from.to_string(),
            channel: channel.to_string(),
            topic: topic.to_string(),
        });
    }

    // Invite a user to a channel, sourced from pseudoclient `from`.
    pub fn invite(&mut self, from: &str, uid: &str, channel: &str) {
        self.actions.push(NetAction::Invite {
            from: from.to_string(),
            uid: uid.to_string(),
            channel: channel.to_string(),
        });
    }
}

// ---------------------------------------------------------------------------
// Store vocabulary
// ---------------------------------------------------------------------------
//
// A service reads and writes accounts and channels through the Store / NetView
// traits, never the concrete storage engine: the append-only log, gossip and
// credential material stay out of reach. Reads hand back plain views that carry
// only non-secret fields (never a password hash or SCRAM verifier).

// A registered account, minus anything credential-shaped.
#[derive(Debug, Clone)]
pub struct AccountView {
    pub name: String,
    pub email: Option<String>,
    pub ts: u64,
    pub verified: bool,
}

// One channel access-list entry (account -> level, e.g. "op" / "voice").
#[derive(Debug, Clone)]
pub struct ChanAccessView {
    pub account: String,
    pub level: String,
}

// One auto-kick entry (a hostmask and the reason shown on kick).
#[derive(Debug, Clone)]
pub struct ChanAkickView {
    pub mask: String,
    pub reason: String,
}

// A registered channel and its ops lists.
#[derive(Debug, Clone)]
pub struct ChannelView {
    pub name: String,
    pub founder: String,
    pub ts: u64,
    // Mode-lock: chars services keep set / unset (besides the implicit +r).
    pub lock_on: String,
    pub lock_off: String,
    pub access: Vec<ChanAccessView>,
    pub akick: Vec<ChanAkickView>,
    pub desc: String,
    pub entrymsg: String,
}

impl ChannelView {
    // The channel mode this account is entitled to on join (+o founder/op, +v
    // voice), or None if it holds no access.
    pub fn join_mode(&self, account: &str) -> Option<&'static str> {
        if self.founder.eq_ignore_ascii_case(account) {
            return Some("+o");
        }
        self.access
            .iter()
            .find(|a| a.account.eq_ignore_ascii_case(account))
            .map(|a| if a.level == "voice" { "+v" } else { "+o" })
    }

    // Whether this account holds channel-operator access (founder or op level).
    pub fn is_op(&self, account: &str) -> bool {
        self.join_mode(account) == Some("+o")
    }

    // The mode-lock rendered as an applyable mode string, e.g. "+rnt-s".
    pub fn lock_modes(&self) -> String {
        let mut s = format!("+r{}", self.lock_on);
        if !self.lock_off.is_empty() {
            s.push('-');
            s.push_str(&self.lock_off);
        }
        s
    }

    // The first auto-kick entry whose mask matches the given hostmask.
    pub fn akick_match(&self, hostmask: &str) -> Option<&ChanAkickView> {
        self.akick.iter().find(|k| glob_match(&k.mask, hostmask))
    }
}

// When a nick was last seen, and doing what.
#[derive(Debug, Clone)]
pub struct SeenView {
    pub nick: String,
    pub ts: u64,
    pub what: String,
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

#[derive(Debug)]
pub enum ChanError {
    Exists,     // channel already registered
    NoChannel,  // channel is not registered
    Internal,   // persistence failed
}

// What an emailed code authorises.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CodeKind {
    Reset,
    Confirm,
}

// The account and channel store a service reads and writes. The engine hands a
// service `&mut dyn Store`; the concrete implementation keeps its log, gossip
// and credentials to itself.
pub trait Store {
    fn exists(&self, name: &str) -> bool;
    fn account(&self, name: &str) -> Option<AccountView>;
    // Canonical account name for a nick (following a grouping), if registered.
    fn resolve_account(&self, name: &str) -> Option<&str>;
    // The canonical account name if the password is correct, else None.
    fn authenticate(&self, name: &str, password: &str) -> Option<&str>;
    fn grouped_nicks(&self, account: &str) -> Vec<String>;
    fn certfps(&self, account: &str) -> &[String];
    fn is_verified(&self, account: &str) -> bool;
    fn channel(&self, name: &str) -> Option<ChannelView>;
    fn channels(&self) -> Vec<ChannelView>;
    fn channels_owned_by(&self, account: &str) -> Vec<String>;
    fn email_enabled(&self) -> bool;
    fn email_brand(&self) -> &str;
    fn email_accent(&self) -> &str;
    fn email_logo(&self) -> &str;

    fn issue_code(&mut self, account: &str, kind: CodeKind) -> String;
    fn take_code(&mut self, account: &str, kind: CodeKind, code: &str) -> bool;
    fn verify_account(&mut self, account: &str) -> Result<(), RegError>;
    fn set_email(&mut self, account: &str, email: Option<String>) -> Result<(), RegError>;
    fn group_nick(&mut self, nick: &str, account: &str) -> Result<(), RegError>;
    fn ungroup_nick(&mut self, nick: &str) -> Result<bool, RegError>;
    fn drop_account(&mut self, account: &str) -> Result<bool, RegError>;
    fn certfp_add(&mut self, account: &str, fp: &str) -> Result<(), CertError>;
    fn certfp_del(&mut self, account: &str, fp: &str) -> Result<bool, CertError>;
    fn register_channel(&mut self, name: &str, founder: &str) -> Result<(), ChanError>;
    fn drop_channel(&mut self, name: &str) -> Result<(), ChanError>;
    fn set_mlock(&mut self, name: &str, on: &str, off: &str) -> Result<(), ChanError>;
    fn set_desc(&mut self, channel: &str, desc: &str) -> Result<(), ChanError>;
    fn set_entrymsg(&mut self, channel: &str, msg: &str) -> Result<(), ChanError>;
    fn set_founder(&mut self, channel: &str, account: &str) -> Result<(), ChanError>;
    fn access_add(&mut self, channel: &str, account: &str, level: &str) -> Result<(), ChanError>;
    fn access_del(&mut self, channel: &str, account: &str) -> Result<bool, ChanError>;
    fn akick_add(&mut self, channel: &str, mask: &str, reason: &str) -> Result<(), ChanError>;
    fn akick_del(&mut self, channel: &str, mask: &str) -> Result<bool, ChanError>;
}

// The live network state a service reads (never mutates directly; changes go out
// as actions on the ServiceCtx).
pub trait NetView {
    fn uid_by_nick(&self, nick: &str) -> Option<&str>;
    fn nick_of(&self, uid: &str) -> Option<&str>;
    fn host_of(&self, uid: &str) -> Option<&str>;
    fn account_of(&self, uid: &str) -> Option<&str>;
    fn uids_logged_into(&self, account: &str) -> Vec<String>;
    fn is_op(&self, channel: &str, uid: &str) -> bool;
    fn channel_members(&self, channel: &str) -> Vec<String>;
    fn channel_key(&self, channel: &str) -> Option<&str>;
    fn last_seen(&self, nick: &str) -> Option<SeenView>;
}

// A pseudo-client (NickServ, ChanServ, ...). Introduced at burst, receives the
// commands users message it, reads/writes the store, and pushes actions.
pub trait Service: Send {
    fn nick(&self) -> &str;
    fn uid(&self) -> &str;
    fn host(&self) -> &str {
        "services.local"
    }
    fn gecos(&self) -> &str;
    // Whether this service owns channel modes (ChanServ), so the engine can source
    // channel mode changes from it.
    fn manages_channels(&self) -> bool {
        false
    }
    // Whether this is the account service (NickServ), so the engine can source
    // account-related notices from it.
    fn manages_accounts(&self) -> bool {
        false
    }
    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, store: &mut dyn Store);
}

// Case-insensitive hostmask glob: `*` (any run) and `?` (one char).
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

// Format a Unix timestamp (seconds) as "YYYY-MM-DD HH:MM:SS UTC", using Howard
// Hinnant's civil-from-days algorithm so no date crate is needed.
pub fn human_time(ts: u64) -> String {
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
