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
    UserConnect { uid: String, nick: String, host: String, ip: String },
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
    // A user's voice status changed (FMODE +v/-v, or a +v join prefix).
    ChannelVoice { channel: String, uid: String, voice: bool },
    // A channel's modes changed (FMODE), for enforcing mode locks. Our own
    // changes are filtered out by the protocol layer.
    ChannelModeChange { channel: String, modes: String },
    // A channel's key (+k/-k) changed, tracked so GETKEY can report it.
    ChannelKey { channel: String, key: Option<String> },
    // A channel's topic changed (FTOPIC), for KEEPTOPIC / TOPICLOCK. `setter` is
    // the source uid; our own changes are filtered out by the protocol layer.
    TopicChange { channel: String, setter: String, topic: String },
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
    // Set a user's displayed host (a vhost), or restore it.
    SetHost { uid: String, host: String },
    // Set a user's displayed ident/username (the `ident@` part of a vhost).
    SetIdent { uid: String, ident: String },
    // Force a user into a channel (SVSJOIN), e.g. applying an account's auto-join
    // list on identify. `key` is empty for keyless channels.
    ForceJoin { uid: String, channel: String, key: String },
    // Remove one of our pseudo-clients (e.g. a deleted bot) from the network.
    QuitUser { uid: String, reason: String },
    // A services pseudo-client (a bot) joins / parts a channel.
    ServiceJoin { uid: String, channel: String },
    ServicePart { uid: String, channel: String },
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
    // Add a network ban (X-line — `kind` is the ircd's line type, e.g. "G" for a
    // G-line) covering `mask`, applied to matching users already online and to
    // future connections. `duration` in seconds, 0 = permanent.
    AddLine { kind: String, mask: String, setter: String, duration: u64, reason: String },
    // Lift a network ban previously set with AddLine.
    DelLine { kind: String, mask: String },
    // Disconnect a user from the network, sourced from pseudoclient `from`.
    KillUser { from: String, uid: String, reason: String },
    // Introduce a juped server (a fake server holding a name so the real one
    // can't link), sourced from our server. `sid` is its allocated server id.
    JupeServer { name: String, sid: String, reason: String },
    // Delink a server (used to lift a jupe), by name or sid.
    Squit { target: String, reason: String },
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

// Whether a channel mode consumes a parameter, given the direction (`adding`).
// The canonical arity for the standard chanmodes, shared by the protocol module
// (parsing bursts) and services (building a MODE change): list and prefix modes
// and the key take a parameter both ways; the rest that take one do so only when
// set. A single source of truth so the two never drift.
pub fn chanmode_takes_param(m: char, adding: bool) -> bool {
    match m {
        'b' | 'e' | 'I' | 'q' | 'a' | 'o' | 'h' | 'v' | 'k' => true,
        'l' | 'L' | 'f' | 'j' | 'J' | 'F' | 'H' => adding,
        _ => false,
    }
}

// The channel prefix (status) modes, whose parameter is a nick/uid rather than a
// mask or value.
pub const STATUS_MODES: &str = "qaohv";

// ---------------------------------------------------------------------------
// Service vocabulary
// ---------------------------------------------------------------------------

// A services-operator privilege. Coarse and typed (not a string namespace), so
// the compiler checks every use and there is one gating mechanism, not two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priv {
    // See other users' hidden info (INFO fields, LIST filters).
    Auspex,
    // Suspend / unsuspend accounts and channels.
    Suspend,
    // Modify or drop other users' accounts and channels (SASET, DROP, GETEMAIL).
    Admin,
}

// The set of privileges a sender holds. A plain Copy bitset — empty means "not
// an oper". Built from the [[oper]] config and carried on every Sender.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Privs(u8);

impl Privs {
    // Grant a privilege (builder style: `Privs::default().with(Priv::Admin)`).
    pub fn with(self, p: Priv) -> Self {
        Privs(self.0 | (1 << p as u8))
    }
    // Whether this set holds `p`.
    pub fn has(self, p: Priv) -> bool {
        self.0 & (1 << p as u8) != 0
    }
    // Whether this is a services operator at all (holds any privilege).
    pub fn any(self) -> bool {
        self.0 != 0
    }

    // The union of two privilege sets (holds a privilege in either).
    pub fn union(self, other: Privs) -> Self {
        Privs(self.0 | other.0)
    }

    // Build a set from privilege names ("auspex"/"suspend"/"admin"), ignoring any
    // that aren't recognised. Shared by the config loader and runtime OPER grants.
    pub fn from_names<S: AsRef<str>>(names: &[S]) -> Self {
        let mut privs = Privs::default();
        for n in names {
            match n.as_ref().to_ascii_lowercase().as_str() {
                "auspex" => privs = privs.with(Priv::Auspex),
                "suspend" => privs = privs.with(Priv::Suspend),
                "admin" => privs = privs.with(Priv::Admin),
                _ => {}
            }
        }
        privs
    }

    // The privilege names held, for display.
    pub fn names(self) -> Vec<&'static str> {
        [(Priv::Auspex, "auspex"), (Priv::Suspend, "suspend"), (Priv::Admin, "admin")]
            .into_iter()
            .filter(|(p, _)| self.has(*p))
            .map(|(_, n)| n)
            .collect()
    }
}

// Who sent the command, resolved by the engine (UID + current nick + the
// account they are identified to, if any, and any oper privileges it holds).
pub struct Sender<'a> {
    pub uid: &'a str,
    pub nick: &'a str,
    pub account: Option<&'a str>,
    pub privs: Privs,
}

// The intent sink a service writes to. A service never mutates the network or
// the store itself; it pushes normalized actions the engine drains and applies.
#[derive(Default)]
pub struct ServiceCtx {
    pub actions: Vec<NetAction>,
    // Namespaced stat counters to bump (e.g. "nickserv.register"). The engine
    // folds these into the shared registry after the command runs — so every
    // service reports its own stats through one shared pipe.
    pub stats: Vec<String>,
}

impl ServiceCtx {
    pub fn notice(&mut self, from: &str, to: &str, text: impl Into<String>) {
        self.actions.push(NetAction::Notice {
            from: from.to_string(),
            to: to.to_string(),
            text: text.into(),
        });
    }

    // Record a stat counter bump (namespaced, e.g. "chanserv.register"). Folded
    // into the engine's shared registry, which the gRPC Stats API exposes.
    pub fn count(&mut self, key: impl Into<String>) {
        self.stats.push(key.into());
    }

    // A channel/target message sourced from one of our pseudo-clients (e.g. a
    // bot answering a fantasy command, or BotServ SAY).
    pub fn privmsg(&mut self, from: &str, to: &str, text: impl Into<String>) {
        self.actions.push(NetAction::Privmsg {
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

    // Set (or restore) a user's displayed host — a HostServ vhost.
    pub fn set_host(&mut self, uid: &str, host: &str) {
        self.actions.push(NetAction::SetHost {
            uid: uid.to_string(),
            host: host.to_string(),
        });
    }

    // Apply a vhost spec to a user: `ident@host` sets both the ident and host,
    // a bare `host` just the host.
    pub fn apply_vhost(&mut self, uid: &str, spec: &str) {
        match spec.split_once('@') {
            Some((ident, host)) => {
                self.actions.push(NetAction::SetIdent { uid: uid.to_string(), ident: ident.to_string() });
                self.set_host(uid, host);
            }
            None => self.set_host(uid, spec),
        }
    }

    // Force a user into a channel (SVSJOIN), e.g. an account's auto-join list.
    pub fn force_join(&mut self, uid: &str, channel: &str, key: &str) {
        self.actions.push(NetAction::ForceJoin {
            uid: uid.to_string(),
            channel: channel.to_string(),
            key: key.to_string(),
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

    // Set a network ban (X-line) at the ircd. `duration` seconds, 0 = permanent.
    pub fn add_line(&mut self, kind: &str, mask: &str, setter: &str, duration: u64, reason: &str) {
        self.actions.push(NetAction::AddLine {
            kind: kind.to_string(),
            mask: mask.to_string(),
            setter: setter.to_string(),
            duration,
            reason: reason.to_string(),
        });
    }

    // Lift a network ban previously set with `add_line`.
    pub fn del_line(&mut self, kind: &str, mask: &str) {
        self.actions.push(NetAction::DelLine { kind: kind.to_string(), mask: mask.to_string() });
    }

    // Disconnect a user, sourced from pseudoclient `from`.
    pub fn kill(&mut self, from: &str, uid: &str, reason: &str) {
        self.actions.push(NetAction::KillUser { from: from.to_string(), uid: uid.to_string(), reason: reason.to_string() });
    }

    // Send a notice to every user on the network, sourced from pseudoclient
    // `from` (a "$*" server-glob target the ircd fans out to all users).
    pub fn global(&mut self, from: &str, text: impl Into<String>) {
        self.actions.push(NetAction::Notice { from: from.to_string(), to: "$*".to_string(), text: text.into() });
    }

    // Introduce a juped server holding `name` (with allocated `sid`).
    pub fn jupe(&mut self, name: &str, sid: &str, reason: &str) {
        self.actions.push(NetAction::JupeServer { name: name.to_string(), sid: sid.to_string(), reason: reason.to_string() });
    }

    // Delink a server by name or sid (lifts a jupe).
    pub fn squit(&mut self, target: &str, reason: &str) {
        self.actions.push(NetAction::Squit { target: target.to_string(), reason: reason.to_string() });
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
    // Personal greet shown by a bot when this account joins a greet-enabled
    // channel (empty = none).
    pub greet: String,
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

// A memo left for an account (MemoServ).
#[derive(Debug, Clone)]
pub struct MemoView {
    pub from: String,
    pub text: String,
    pub ts: u64,
    pub read: bool,
}

// A service bot registered with BotServ.
#[derive(Debug, Clone)]
pub struct TriggerView {
    pub pattern: String,
    pub response: String,
    pub cooldown: u32,
}

#[derive(Debug, Clone)]
pub struct VhostView {
    pub account: String,
    pub host: String,
    pub setter: String,
    pub expires: Option<u64>,
}

// A network ban held by OperServ. `kind` is the ircd X-line type ("G", "Q", …).
#[derive(Debug, Clone)]
pub struct AkillView {
    pub kind: String,
    pub mask: String,
    pub setter: String,
    pub reason: String,
    pub ts: u64,
    pub expires: Option<u64>,
}

// A services ignore held by OperServ.
#[derive(Debug, Clone)]
pub struct IgnoreView {
    pub mask: String,
    pub reason: String,
    pub expires: Option<u64>,
}

// A news item held by OperServ (its kind is implied by which list it came from).
#[derive(Debug, Clone)]
pub struct NewsView {
    pub id: u64,
    pub text: String,
    pub setter: String,
    pub ts: u64,
}

// An abuse report held by ReportServ.
#[derive(Debug, Clone)]
pub struct ReportView {
    pub id: u64,
    pub reporter: String,
    pub target: String,
    pub reason: String,
    pub ts: u64,
    pub open: bool,
}

#[derive(Debug, Clone)]
pub struct BotView {
    pub nick: String,
    pub user: String,
    pub host: String,
    pub gecos: String,
    // A private bot may only be assigned by a services admin and is hidden from
    // BOT LIST for everyone else.
    pub private: bool,
}

// A services suspension on an account: who, why, when, and an optional expiry
// (absolute unix seconds; None = until manually lifted).
#[derive(Debug, Clone)]
pub struct SuspensionView {
    pub by: String,
    pub reason: String,
    pub ts: u64,
    pub expires: Option<u64>,
}

// One auto-join entry: a channel joined on identify, with an optional key.
#[derive(Debug, Clone)]
pub struct AjoinView {
    pub channel: String,
    pub key: String,
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
    // ChanServ SET options.
    pub signkick: bool,
    pub private: bool,
    pub peace: bool,
    pub secureops: bool,
    pub keeptopic: bool,
    pub topiclock: bool,
    pub suspended: bool,
    // Last known topic (for KEEPTOPIC / TOPICLOCK).
    pub topic: String,
    // BotServ bot assigned to this channel, if any.
    pub assigned_bot: Option<String>,
    // BotServ: whether members' personal greets are shown on join.
    pub bot_greet: bool,
    // BotServ: whether the founder is barred from (un)assigning a bot.
    pub nobot: bool,
    // BotServ: whether any message kicker is active on this channel.
    pub kickers_active: bool,
}

// A single ChanServ SET option, named for the typed `set_channel_setting` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChanSetting {
    SignKick,
    Private,
    Peace,
    SecureOps,
    KeepTopic,
    TopicLock,
    // BotServ: show members' personal greets on join.
    BotGreet,
    // BotServ: forbid the founder from (un)assigning a bot (admin override only).
    NoBot,
}

// A BotServ kicker: the assigned bot kicks a message that trips an enabled one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kicker {
    Caps,
    Bolds,
    Colors,
    Underlines,
    Reverses,
    Italics,
    Flood,
    Repeat,
    // Kick lines matching a configured badword regex (patterns via BADWORDS).
    Badwords,
    // Modifier: warn once before the first kick.
    Warn,
    // Exemption, not a rule: never kick channel operators.
    DontKickOps,
    // Exemption: never kick voiced users.
    DontKickVoices,
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

    // A comparable access rank for PEACE: founder 3, op 2, voice 1, none 0.
    pub fn access_rank(&self, account: Option<&str>) -> u8 {
        let Some(acc) = account else { return 0 };
        if self.founder.eq_ignore_ascii_case(acc) {
            return 3;
        }
        self.access
            .iter()
            .find(|a| a.account.eq_ignore_ascii_case(acc))
            .map_or(0, |a| if a.level == "voice" { 1 } else { 2 })
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
    Exists,         // channel already registered
    NoChannel,      // channel is not registered
    InvalidPattern, // a badword regex didn't compile
    Internal,       // persistence failed
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
    // Brute-force throttle for password authentication: how long the account is
    // locked out (if at all), and a hook to record each attempt's outcome.
    fn auth_lockout(&self, account: &str) -> Option<u64>;
    fn note_auth(&mut self, account: &str, success: bool);
    fn verify_account(&mut self, account: &str) -> Result<(), RegError>;
    fn set_email(&mut self, account: &str, email: Option<String>) -> Result<(), RegError>;
    fn set_greet(&mut self, account: &str, greet: &str) -> Result<(), RegError>;
    // HostServ vhosts.
    fn set_vhost(&mut self, account: &str, host: &str, setter: &str, ttl: Option<u64>) -> Result<(), RegError>;
    fn del_vhost(&mut self, account: &str) -> Result<bool, RegError>;
    fn vhost(&self, account: &str) -> Option<VhostView>;
    fn vhosts(&self) -> Vec<VhostView>;
    fn vhost_owner(&self, host: &str) -> Option<String>;
    fn request_vhost(&mut self, account: &str, host: &str) -> Result<(), RegError>;
    fn vhost_request_wait(&self, account: &str) -> u64;
    fn take_vhost_request(&mut self, account: &str) -> Result<Option<String>, RegError>;
    fn vhost_requests(&self) -> Vec<(String, String)>;
    fn vhost_offer_add(&mut self, host: &str) -> Result<bool, RegError>;
    fn vhost_offer_del(&mut self, index: usize) -> Result<Option<String>, RegError>;
    fn vhost_offers(&self) -> Vec<String>;
    fn vhost_forbid_add(&mut self, pattern: &str) -> Result<bool, RegError>;
    fn vhost_forbid_del(&mut self, index: usize) -> Result<Option<String>, RegError>;
    fn vhost_forbidden(&self) -> Vec<String>;
    fn vhost_is_forbidden(&self, host: &str) -> bool;
    fn set_vhost_template(&mut self, template: Option<String>) -> Result<(), RegError>;
    fn vhost_template(&self) -> Option<String>;
    fn group_nick(&mut self, nick: &str, account: &str) -> Result<(), RegError>;
    fn ungroup_nick(&mut self, nick: &str) -> Result<bool, RegError>;
    fn drop_account(&mut self, account: &str) -> Result<bool, RegError>;
    fn certfp_add(&mut self, account: &str, fp: &str) -> Result<(), CertError>;
    fn certfp_del(&mut self, account: &str, fp: &str) -> Result<bool, CertError>;
    // Per-account auto-join list (AJOIN): channels the user is SVSJOINed to on identify.
    fn ajoin_list(&self, account: &str) -> Vec<AjoinView>;
    fn ajoin_add(&mut self, account: &str, channel: &str, key: &str) -> Result<bool, RegError>;
    fn ajoin_del(&mut self, account: &str, channel: &str) -> Result<bool, RegError>;
    // Suspension (oper-only, gated on Priv::Suspend at the command layer).
    fn suspend_account(&mut self, account: &str, by: &str, reason: &str, expires: Option<u64>) -> Result<(), RegError>;
    fn unsuspend_account(&mut self, account: &str) -> Result<bool, RegError>;
    fn is_suspended(&self, account: &str) -> bool;
    fn suspension(&self, account: &str) -> Option<SuspensionView>;
    // Inactivity-expiry pins (oper-only, gated on Priv::Admin at the command layer).
    fn set_account_noexpire(&mut self, account: &str, on: bool) -> Result<bool, RegError>;
    fn set_channel_noexpire(&mut self, channel: &str, on: bool) -> Result<bool, ChanError>;
    // Network bans (AKILL / G-lines, oper-only). `akill_add` returns whether the
    // mask was newly added (false = an existing entry was refreshed); `akills`
    // lists only entries that haven't lazily expired, oldest first.
    fn akill_add(&mut self, kind: &str, mask: &str, setter: &str, reason: &str, expires: Option<u64>) -> Result<bool, RegError>;
    fn akill_del(&mut self, kind: &str, mask: &str) -> Result<bool, RegError>;
    fn akills(&self) -> Vec<AkillView>;
    // Services ignores (node-local, oper-only).
    fn ignore_add(&mut self, mask: &str, reason: &str, expires: Option<u64>);
    fn ignore_del(&mut self, mask: &str) -> bool;
    fn ignores(&self) -> Vec<IgnoreView>;
    // Juped servers (node-local, oper-only). jupe_add returns the allocated sid;
    // jupe_del returns the sid to squit if it existed.
    fn jupe_add(&mut self, name: &str, reason: &str) -> String;
    fn jupe_del(&mut self, name: &str) -> Option<String>;
    fn jupes(&self) -> Vec<(String, String, String)>;
    // Network defence level (OperServ DEFCON) and its derived registration freezes.
    fn defcon(&self) -> u8;
    fn set_defcon(&mut self, level: u8);
    fn registrations_frozen(&self) -> bool;
    fn channel_regs_frozen(&self) -> bool;
    // Whether account identity is owned externally (website); when true, IRC
    // can't register or change credentials — it only authenticates.
    fn external_accounts(&self) -> bool;
    // Staff notes on accounts/channels (oper-only), shown in INFO to operators.
    fn set_account_note(&mut self, account: &str, note: Option<String>) -> bool;
    fn account_note(&self, account: &str) -> Option<String>;
    fn set_channel_note(&mut self, channel: &str, note: Option<String>) -> bool;
    fn channel_note(&self, channel: &str) -> Option<String>;
    // News items shown on connect (logon) / login (oper), oper-only to manage.
    fn news_add(&mut self, kind: &str, text: &str, setter: &str) -> u64;
    fn news_del(&mut self, id: u64) -> bool;
    fn news(&self, kind: &str) -> Vec<NewsView>;
    // Abuse reports (ReportServ). `report_file` is rate-limited (None = too soon).
    fn report_file(&mut self, reporter: &str, target: &str, reason: &str) -> Option<u64>;
    fn report_close(&mut self, id: u64) -> bool;
    fn report_del(&mut self, id: u64) -> bool;
    fn reports(&self, open_only: bool) -> Vec<ReportView>;
    fn report(&self, id: u64) -> Option<ReportView>;
    // Runtime operator grants (OperServ OPER), merged with config opers. `expires`
    // is an absolute unix time (None = permanent); opers_list hides expired ones.
    fn oper_grant(&mut self, account: &str, privs: Vec<String>, expires: Option<u64>);
    fn oper_revoke(&mut self, account: &str) -> bool;
    fn opers_list(&self) -> Vec<(String, Vec<String>, Option<u64>)>;
    // Session-limit exceptions (OperServ SESSION EXCEPTION).
    fn session_except_add(&mut self, mask: &str, limit: u32, reason: &str);
    fn session_except_del(&mut self, mask: &str) -> bool;
    fn session_exceptions(&self) -> Vec<(String, u32, String)>;
    fn register_channel(&mut self, name: &str, founder: &str) -> Result<(), ChanError>;
    fn drop_channel(&mut self, name: &str) -> Result<(), ChanError>;
    fn set_mlock(&mut self, name: &str, on: &str, off: &str) -> Result<(), ChanError>;
    fn set_desc(&mut self, channel: &str, desc: &str) -> Result<(), ChanError>;
    fn set_channel_setting(&mut self, channel: &str, setting: ChanSetting, on: bool) -> Result<(), ChanError>;
    fn set_kicker(&mut self, channel: &str, kicker: Kicker, on: bool) -> Result<(), ChanError>;
    fn set_caps_kicker(&mut self, channel: &str, caps_min: u16, caps_percent: u16) -> Result<(), ChanError>;
    fn set_flood_kicker(&mut self, channel: &str, lines: u16, secs: u16) -> Result<(), ChanError>;
    fn set_repeat_kicker(&mut self, channel: &str, times: u16) -> Result<(), ChanError>;
    fn set_ttb(&mut self, channel: &str, ttb: u16) -> Result<(), ChanError>;
    fn set_ban_expire(&mut self, channel: &str, secs: u32) -> Result<(), ChanError>;
    fn set_votekick(&mut self, channel: &str, votes: u16) -> Result<(), ChanError>;
    // BADWORDS list (regex patterns). add validates the pattern compiles.
    fn badword_add(&mut self, channel: &str, pattern: &str) -> Result<bool, ChanError>;
    fn badword_del(&mut self, channel: &str, pattern: &str) -> Result<bool, ChanError>;
    fn badword_clear(&mut self, channel: &str) -> Result<usize, ChanError>;
    fn badwords(&self, channel: &str) -> Vec<String>;
    // Dry-run the content kickers against a line; Some(reason) if it would kick.
    fn kicker_test(&self, channel: &str, text: &str) -> Option<String>;
    // Copy one channel's BotServ config (kickers/badwords/greet/nobot) to another.
    fn copy_bot_config(&mut self, src: &str, dst: &str) -> Result<(), ChanError>;
    // Auto-response triggers (regex -> response).
    fn trigger_add(&mut self, channel: &str, pattern: &str, response: &str, cooldown: u32) -> Result<bool, ChanError>;
    fn trigger_del(&mut self, channel: &str, index: usize) -> Result<bool, ChanError>;
    fn trigger_clear(&mut self, channel: &str) -> Result<usize, ChanError>;
    fn triggers(&self, channel: &str) -> Vec<TriggerView>;
    fn set_channel_topic(&mut self, channel: &str, topic: &str) -> Result<(), ChanError>;
    fn suspend_channel(&mut self, channel: &str, by: &str, reason: &str, expires: Option<u64>) -> Result<(), ChanError>;
    fn unsuspend_channel(&mut self, channel: &str) -> Result<bool, ChanError>;
    fn is_channel_suspended(&self, channel: &str) -> bool;
    fn channel_suspension(&self, channel: &str) -> Option<SuspensionView>;
    // BotServ registry (oper-only at the command layer).
    fn bot_add(&mut self, nick: &str, user: &str, host: &str, gecos: &str) -> Result<(), ChanError>;
    fn bot_change(&mut self, old: &str, new_nick: &str, user: &str, host: &str, gecos: &str) -> Result<(), ChanError>;
    fn bot_set_private(&mut self, nick: &str, private: bool) -> Result<bool, ChanError>;
    fn bot_del(&mut self, nick: &str) -> Result<bool, ChanError>;
    fn bot_del_all(&mut self) -> Result<usize, ChanError>;
    fn bots(&self) -> Vec<BotView>;
    fn assign_bot(&mut self, channel: &str, bot: &str) -> Result<(), ChanError>;
    fn unassign_bot(&mut self, channel: &str) -> Result<bool, ChanError>;
    // MemoServ: per-account memos (index is a 0-based position in memo_list).
    fn memo_send(&mut self, account: &str, from: &str, text: &str) -> Result<(), RegError>;
    fn memo_list(&self, account: &str) -> Vec<MemoView>;
    fn memo_read(&mut self, account: &str, index: usize) -> Option<MemoView>;
    fn memo_del(&mut self, account: &str, index: usize) -> bool;
    fn unread_memos(&self, account: &str) -> usize;
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
    // BOTSTATS: (lines seen this session, top talkers by count desc).
    fn channel_activity(&self, channel: &str) -> Option<(u64, Vec<(String, u64)>)>;
    // The shared stat counters (namespaced key -> count), for StatServ.
    fn stat_counters(&self) -> Vec<(String, u64)>;
    // Session limiting: live sessions from an IP, and IPs at/over a threshold.
    fn session_count(&self, ip: &str) -> u32;
    fn sessions_over(&self, min: u32) -> Vec<(String, u32)>;
    // Search the recent moderation/action incident log (newest first, capped at
    // `limit`). An empty pattern returns the most recent; otherwise matches the
    // id or a case-insensitive substring of the summary.
    fn search_incidents(&self, pattern: &str, limit: usize) -> Vec<IncidentView>;
}

// One recorded action from the incident log: a short id (also stamped into the
// action's reason), when it happened, and a human summary.
#[derive(Debug, Clone)]
pub struct IncidentView {
    pub id: String,
    pub ts: u64,
    pub summary: String,
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

// Parse a duration like "30d", "12h", "45m", "90s", or bare seconds. Shared by
// the SUSPEND commands.
pub fn parse_duration(s: &str) -> Option<u64> {
    let (num, mult) = match s.chars().last()? {
        'd' | 'D' => (&s[..s.len() - 1], 86_400),
        'h' | 'H' => (&s[..s.len() - 1], 3_600),
        'm' | 'M' => (&s[..s.len() - 1], 60),
        's' | 'S' => (&s[..s.len() - 1], 1),
        c if c.is_ascii_digit() => (s, 1),
        _ => return None,
    };
    num.parse::<u64>().ok().map(|n| n * mult)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privs_bitset_grants_and_checks() {
        let p = Privs::default().with(Priv::Auspex).with(Priv::Admin);
        assert!(p.has(Priv::Auspex) && p.has(Priv::Admin));
        assert!(!p.has(Priv::Suspend), "only granted privileges are held");
        assert!(p.any());
        assert!(!Privs::default().any(), "empty set is not an oper");
    }
}
