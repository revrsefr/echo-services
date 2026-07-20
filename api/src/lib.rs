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
    // A remote server asks for one of our pseudo-clients' idle/signon time — the
    // idle half of a routed WHOIS (`WHOIS x x` / mIRC's double-click). Must be
    // answered or that WHOIS produces no output at all.
    Idle { requester: String, target: String },
    Privmsg { from: String, to: String, text: String },
    UserConnect { uid: String, nick: String, host: String, ip: String },
    // The rest of a user's UID that UserConnect omits — ident, real host, and
    // real name (gecos). The ircd sends them in the same UID line; extban
    // matching (AKICK) needs them. Emitted right after UserConnect.
    UserAttrs { uid: String, ident: String, realhost: String, gecos: String },
    NickChange { uid: String, nick: String },
    // The ircd tells us a user's logged-in account (METADATA accountname), e.g.
    // replayed on a services netburst so we can restore who was identified. An
    // empty `account` means they logged out.
    AccountLogin { uid: String, account: String },
    // A channel was created or bursted (an FJOIN). Subsequent single joins arrive
    // as IJOIN and are not surfaced.
    ChannelCreate { channel: String },
    // A user joined a channel (an FJOIN member or an IJOIN), for auto-op. `op` is
    // whether they hold channel-operator status at that point (an FJOIN prefix).
    Join { uid: String, channel: String, op: bool },
    // A user left a channel (PART), for membership tracking. `reason` is the part
    // message (may be empty).
    Part { uid: String, channel: String, reason: String },
    // A user was kicked from a channel: `by` is the kicker's uid, `reason` the kick
    // message. Membership is dropped the same as a part.
    Kicked { channel: String, uid: String, by: String, reason: String },
    // A user's own modes changed (`:uid MODE uid <modes>`), e.g. going +i. Our own
    // pseudo-clients are filtered out by the protocol layer.
    UserMode { uid: String, modes: String },
    // A user became a network operator (`OPERTYPE`). `oper_type` is the oper class
    // WHOIS shows. Our own services opering themselves are filtered out.
    OperUp { uid: String, oper_type: String },
    // A user's channel-operator status changed (FMODE +o/-o), for live op tracking.
    ChannelOp { channel: String, uid: String, op: bool },
    // A user's voice status changed (FMODE +v/-v, or a +v join prefix).
    ChannelVoice { channel: String, uid: String, voice: bool },
    // A channel's modes changed (FMODE), for enforcing mode locks. `setter` is the
    // source uid (empty for a server). Our own changes are filtered by the protocol.
    ChannelModeChange { channel: String, modes: String, setter: String },
    // A channel's key (+k/-k) changed, tracked so GETKEY can report it.
    ChannelKey { channel: String, key: Option<String> },
    // A channel's topic changed (FTOPIC), for KEEPTOPIC / TOPICLOCK. `setter` is
    // the source uid; our own changes are filtered out by the protocol layer.
    TopicChange { channel: String, setter: String, topic: String },
    // A user disconnected (QUIT). `reason` is the quit message (may be empty).
    Quit { uid: String, reason: String },
    // A user was forcibly removed (KILL). Handled like a quit, except a killed
    // services bot is reintroduced rather than forgotten.
    UserKilled { uid: String },
    // A downstream server was introduced (a sourced SERVER). `parent` is the SID
    // that introduced it, so we can track the tree and cascade a hub's SQUIT.
    ServerLink { sid: String, parent: String },
    // A server's SID-to-name mapping (from any SERVER line, uplink or downstream),
    // so the `server` extban can match a user by the server they're on.
    ServerInfo { sid: String, name: String },
    // A user's TLS client-certificate fingerprint (ircd `ssl_cert` metadata), for
    // the `fingerprint` extban. Empty `fp` means the user has no cert.
    UserCert { uid: String, fp: String },
    // The ircd's live extban set from its `CAPAB EXTBANS` burst — the authoritative
    // list AKICK/MODE validate against, replacing echo's static guess.
    ExtbanRegistry { entries: Vec<ExtbanCap> },
    // The ircd's live channel-mode set from its `CAPAB CHANMODES` burst — mode
    // letters, param arity, and prefix (status) modes incl custom ones like `Y`.
    ChanModeRegistry { modes: Vec<ChanModeCap> },
    // The ircd's `CASEMAPPING` from its `CAPAB CAPABILITIES` burst. echo folds
    // identifiers as ascii, so it verifies this matches and warns otherwise.
    Casemapping { name: String },
    // Module names the ircd advertises (`CAPAB MODULES` / `MODSUPPORT`), normalized
    // (no `m_`/`.so`/`=data`). Accumulated to verify echo's dependencies.
    ModulesAvailable { modules: Vec<String> },
    // `CAPAB END` — the module lists are complete; verify dependencies now.
    CapabEnd,
    // The ircd's `servprotect` user mode (from CAPAB USERMODES) and whether echo's
    // configured service_modes request it — a services pseudoclient without it can
    // be killed/hijacked by an operator.
    ServProtect { letter: char, requested: bool },
    // A server split away (SQUIT). `server` is its SID; every user behind it — and
    // behind any server in its subtree — is gone, since a split is signalled once
    // rather than as a QUIT per user.
    ServerSplit { server: String },
    // An ircd relaying an IRCv3 account-registration request to us as the authority.
    AccountRequest { reqid: String, origin: String, kind: String, account: String, p2: String, p3: String },
    // An ircd relaying a SASL exchange step to us (the SASL agent). mode = H/S/C/D.
    Sasl { client: String, agent: String, mode: String, data: Vec<String> },
    Unknown { line: String },
}

// The three IRCv3 standard-reply verbs (https://ircv3.net/specs/extensions/standard-replies).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyKind { Fail, Warn, Note }

impl ReplyKind {
    pub fn verb(self) -> &'static str {
        match self {
            ReplyKind::Fail => "FAIL",
            ReplyKind::Warn => "WARN",
            ReplyKind::Note => "NOTE",
        }
    }
}

// Normalized outbound intents the engine wants performed on the network.
#[derive(Debug, Clone)]
pub enum NetAction {
    Burst,
    EndBurst,
    Pong { token: String, from: Option<String> },
    // Answer a remote IDLE request for one of our pseudo-clients so a routed
    // WHOIS completes: `:<target> IDLE <requester> <signon> <idle>`.
    IdleReply { target: String, requester: String, signon: u64, idle: u64 },
    // Flag one of our pseudo-clients as a services operator so WHOIS labels it a
    // network service (the oper line): `:<uid> OPERTYPE :<oper_type>`.
    OperType { uid: String, oper_type: String },
    IntroduceUser { uid: String, nick: String, ident: String, host: String, gecos: String },
    Privmsg { from: String, to: String, text: String },
    Notice { from: String, to: String, text: String },
    // An IRCv3 standard reply (FAIL/WARN/NOTE) from a service to a client. Not
    // routable over s2s directly, so it's encapsulated for the target's server
    // (m_services_stdrpl) to re-emit locally, cap-gated. `command`/`from` may be
    // "*" for none/server-sourced. Degrades to a Notice when the feature is off.
    StandardReply { kind: ReplyKind, from: String, to: String, command: String, code: String, text: String },
    AccountResponse { reqid: String, origin: String, kind: String, account: String, status: String, code: String, message: String },
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
    ForcePart { uid: String, channel: String, reason: String },
    // Remove one of our pseudo-clients (e.g. a deleted bot) from the network.
    QuitUser { uid: String, reason: String },
    // A services pseudo-client (a bot) joins / parts a channel. `modes` are the
    // status-mode letters it joins with: "ao" (protected admin + op) for BotServ
    // bots, "o" for the core service pseudo-clients in the services channel.
    ServiceJoin { uid: String, channel: String, modes: String },
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
    // Redact (delete) a message by its msgid, sourced from a pseudoclient. `target`
    // is a channel or a uid; `reason` is optional (empty = none). draft/message-redaction.
    Redact { from: String, target: String, msgid: String, reason: String },
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
    // Internal only: a password VERIFY (IDENTIFY / SASL PLAIN) awaiting the same
    // off-thread work — the PBKDF2 that verify_plain runs is ~1s at production
    // iteration counts, so it must never run under the engine lock. The link layer
    // fetches `verifier` cheaply, runs verify_plain off-thread, then calls
    // Engine::complete_authenticate with the boolean result and `then`.
    DeferAuthenticate { verifier: String, password: String, then: AuthThen },
    // Internal only: redeem a website login keycard (`kc_…`) off-thread. The
    // credential isn't a password, so it can't be SCRAM-verified; the link layer
    // redeems `token` for `account` against Django's localhost login-token
    // endpoint, then calls Engine::complete_authenticate with the result + `then`.
    DeferKeycard { token: String, account: String, then: AuthThen },
    // Internal only: send an email (plaintext + optional HTML). The link layer
    // pipes it to the configured mail command off-thread; never serialized.
    SendEmail { to: String, subject: String, text: String, html: Option<String> },
    // Internal only: look up `query` on a DICT server (RFC 2229) off the reactor,
    // then speak the result as `speak_as` to `target` — a #channel (a fantasy
    // lookup, spoken by the assigned bot) or a user (a direct DictServ query).
    // `label` is the human dictionary name for the reply. Never serialized.
    DictLookup { speak_as: String, target: String, database: String, label: String, query: String },
    // Internal only: stop the services process (OperServ SHUTDOWN/RESTART). The
    // link layer exits cleanly; `restart` exits non-zero so a supervisor (systemd
    // Restart=) brings it back. Never serialized.
    Shutdown { restart: bool, reason: String },
    // Internal only: re-read config.toml and apply the reloadable settings to the
    // running engine (OperServ REHASH). The link layer resolves it against the
    // engine and sends the outcome back to `requester` from `agent`. Never
    // serialized as-is.
    Rehash { requester: String, agent: String },
}

// How to answer a registration once its credentials have been derived.
#[derive(Debug, Clone)]
pub enum RegReply {
    // IRCv3 account-registration relay: answer the requesting ircd. `origin` is
    // the server the request came from, which the response is ENCAP'd back to.
    Relay { reqid: String, kind: String, origin: String },
    // NickServ REGISTER: NOTICE the requesting user, logging them in on success.
    NickServ { agent: String, uid: String, nick: String },
}

/// What to do once a deferred password verify (see [`NetAction::DeferAuthenticate`])
/// completes, given the boolean result. The cheap pre-checks already ran; this is
/// only the success/failure finish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthThen {
    // NickServ IDENTIFY: `uid` logs in, `agent` (NickServ uid) sends the notices,
    // `name` is what the user typed (for lockout/note_auth), `account` is canonical.
    Identify { uid: String, agent: String, name: String, account: String },
    // SASL: finish the exchange for `client`, sourced from `agent`. `password` is
    // whether this was a password verify (feeds the brute-force throttle) vs a
    // one-time keycard redemption (which must not touch the password lockout).
    Sasl { agent: String, client: String, account: String, password: bool },
}

/// The ircd link layer. The engine only ever sees [`NetEvent`] / [`NetAction`];
/// raw server-to-server lines live entirely behind a `Protocol` impl, so a new
/// ircd is one new module and the engine is untouched.
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
// set. Used as the fallback before the ircd's live CAPAB CHANMODES set is learned.
pub fn chanmode_takes_param(m: char, adding: bool) -> bool {
    match m {
        'b' | 'e' | 'I' | 'q' | 'a' | 'o' | 'h' | 'v' | 'k' => true,
        'l' | 'L' | 'f' | 'j' | 'J' | 'F' | 'H' => adding,
        _ => false,
    }
}

// The channel prefix (status) modes, whose parameter is a nick/uid rather than a
// mask or value. Fallback before the ircd's live prefix set is learned.
pub const STATUS_MODES: &str = "qaohv";

/// How a channel mode consumes its parameter, from the ircd's `CAPAB CHANMODES`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChanModeKind {
    List,                              // param on set + unset (b/e/I)
    ParamAlways,                       // param on set + unset (k)
    ParamSet,                          // param on set only (l)
    Simple,                            // no param (n/t/s/...)
    Prefix { symbol: char, rank: u32 }, // status mode: +v/@o/!Y, param is a nick
}

/// One channel mode the linked ircd advertises: its letter and how it takes a
/// parameter. Learned from `CAPAB CHANMODES` so echo's mode handling matches the
/// ircd exactly (custom param modes, and prefix modes like ojoin's `Y`/`!`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChanModeCap {
    pub letter: char,
    pub kind: ChanModeKind,
}

impl ChanModeCap {
    /// Whether this mode consumes a parameter in the given direction.
    pub fn takes_param(&self, adding: bool) -> bool {
        match self.kind {
            ChanModeKind::Simple => false,
            ChanModeKind::ParamSet => adding,
            _ => true, // list, param-always, prefix: a param both ways
        }
    }
    pub fn is_prefix(&self) -> bool {
        matches!(self.kind, ChanModeKind::Prefix { .. })
    }
}

// ---------------------------------------------------------------------------
// Service vocabulary
// ---------------------------------------------------------------------------

// A services-operator privilege. Coarse and typed (not a string namespace), so
// the compiler checks every use and there is one gating mechanism, not two.
// A services-operator privilege, ordered as tiers: a higher one implies the lower
// ones (see `Privs::has`), so three named tiers — operator, administrator, root —
// fall out of single privileges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priv {
    // See other users' hidden info (INFO fields, LIST filters).
    Auspex,
    // Front-line moderation: network bans (AKILL/x-lines), KICK, KILL, SESSION,
    // IGNORE, MODE, SPAMFILTER, NOTIFY, stats — the day-to-day operator tools.
    Oper,
    // Suspend / unsuspend accounts and channels.
    Suspend,
    // Persistent data + broadcast: modify/drop accounts+channels (SASET, DROP,
    // GETEMAIL, NOEXPIRE), FORBID, GLOBAL, DEFCON, SVS, JUPE, and the BotServ /
    // MemoServ / InfoServ staff tools.
    Admin,
    // Control the services daemon and the oper roster: OPER (grant/revoke opers),
    // SHUTDOWN / RESTART, REHASH, OperServ SET, DebugServ.
    Root,
}

impl Priv {
    /// Every privilege, low tier to high, for iteration and validation.
    pub const ALL: [Priv; 5] = [Priv::Auspex, Priv::Oper, Priv::Suspend, Priv::Admin, Priv::Root];

    /// This privilege's canonical name — the `[[oper]]` config token. Exhaustive,
    /// so adding a variant forces adding its name (no silent gap).
    pub fn name(self) -> &'static str {
        match self {
            Priv::Auspex => "auspex",
            Priv::Oper => "oper",
            Priv::Suspend => "suspend",
            Priv::Admin => "admin",
            Priv::Root => "root",
        }
    }

    /// Parse a privilege name (case-insensitive), accepting the tier aliases
    /// `operator`/`administrator`; `None` if unrecognised.
    pub fn from_name(s: &str) -> Option<Priv> {
        match s.to_ascii_lowercase().as_str() {
            "auspex" => Some(Priv::Auspex),
            "oper" | "operator" => Some(Priv::Oper),
            "suspend" => Some(Priv::Suspend),
            "admin" | "administrator" => Some(Priv::Admin),
            "root" => Some(Priv::Root),
            _ => None,
        }
    }

    /// The recognised names as a comma list, for "valid: …" error messages.
    pub fn valid_names() -> String {
        Self::ALL.iter().map(|p| p.name()).collect::<Vec<_>>().join(", ")
    }
}

// The set of privileges a sender holds. A plain Copy bitset — empty means "not
// an oper". Built from the [[oper]] config and carried on every Sender.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Privs(u8);

impl Privs {
    fn bit(p: Priv) -> u8 {
        1 << p as u8
    }
    // Grant a privilege (builder style: `Privs::default().with(Priv::Admin)`).
    pub fn with(self, p: Priv) -> Self {
        Privs(self.0 | Self::bit(p))
    }
    // Whether this set can exercise `p`, honouring the tier chain: a higher tier
    // implies the lower ones — Root ⊃ Admin ⊃ Oper ⊃ Auspex — and Admin also bundles
    // Suspend. So an `admin` gates through an `oper`-level command and can view, but
    // a stand-alone `suspend` grant is only that (it doesn't imply Auspex).
    pub fn has(self, p: Priv) -> bool {
        let b = Self::bit;
        let mask = match p {
            Priv::Auspex => b(Priv::Auspex) | b(Priv::Oper) | b(Priv::Admin) | b(Priv::Root),
            Priv::Oper => b(Priv::Oper) | b(Priv::Admin) | b(Priv::Root),
            Priv::Suspend => b(Priv::Suspend) | b(Priv::Admin) | b(Priv::Root),
            Priv::Admin => b(Priv::Admin) | b(Priv::Root),
            Priv::Root => b(Priv::Root),
        };
        self.0 & mask != 0
    }
    // Whether `p` was granted literally (no tier implication) — for display, not
    // gating.
    pub fn contains(self, p: Priv) -> bool {
        self.0 & Self::bit(p) != 0
    }
    // The named tier this set belongs to: the highest tier gate it actually
    // clears. Uses `has` (not `contains`) so the label never claims more than the
    // set can do — a `suspend`- or `auspex`-only grant doesn't clear the operator
    // floor, so it's reported as a limited operator, not a full one.
    pub fn tier(self) -> &'static str {
        if self.has(Priv::Root) {
            "Services Root"
        } else if self.has(Priv::Admin) {
            "Services Administrator"
        } else if self.has(Priv::Oper) {
            "Services Operator"
        } else if self.any() {
            // Holds a privilege but not the operator floor: a view-only (auspex)
            // or suspend-only grant. A real role, but narrower than a named tier.
            "limited operator"
        } else {
            "not an operator"
        }
    }
    // Whether this is a services operator at all (holds any privilege).
    pub fn any(self) -> bool {
        self.0 != 0
    }

    // The union of two privilege sets (holds a privilege in either).
    pub fn union(self, other: Privs) -> Self {
        Privs(self.0 | other.0)
    }

    // Build a set from privilege names, returning the parsed set AND any names that
    // weren't recognised — so a caller (config load, REHASH) can surface a typo
    // loudly instead of silently granting nothing.
    pub fn parse_names<S: AsRef<str>>(names: &[S]) -> (Self, Vec<String>) {
        let mut privs = Privs::default();
        let mut unknown = Vec::new();
        for n in names {
            match Priv::from_name(n.as_ref()) {
                Some(p) => privs = privs.with(p),
                None => unknown.push(n.as_ref().to_string()),
            }
        }
        (privs, unknown)
    }

    // Build a set from privilege names, ignoring any that aren't recognised. Use
    // [`Privs::parse_names`] where a typo should be surfaced.
    pub fn from_names<S: AsRef<str>>(names: &[S]) -> Self {
        Self::parse_names(names).0
    }

    // The privilege names granted literally (not implied), for display.
    pub fn names(self) -> Vec<&'static str> {
        Priv::ALL.into_iter().filter(|p| self.contains(*p)).map(Priv::name).collect()
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

// ── Localization (i18n) ─────────────────────────────────────────────────────
// Messages are authored in English at the call site (the English string is the
// message id). A per-language catalog maps that id to a translation; `render`
// looks it up for the target language and substitutes `{name}` placeholders. With
// no catalog loaded, or no entry, the English id is used verbatim — so English is
// always the zero-config fallback and untranslated messages degrade gracefully.
static CATALOG: std::sync::OnceLock<std::collections::HashMap<String, std::collections::HashMap<String, String>>> = std::sync::OnceLock::new();

/// Install the translation catalog: `lang code -> (english msgid -> translation)`.
/// Called once at startup; a no-op if already set.
pub fn load_catalog(catalog: std::collections::HashMap<String, std::collections::HashMap<String, String>>) {
    let _ = CATALOG.set(catalog);
}

/// Render `msgid` (the English template) into `lang`, substituting `{name}`
/// placeholders from `args`. Falls back to the English `msgid` when there is no
/// translation. Used via the [`t!`] macro; rarely called directly.
pub fn render(lang: &str, msgid: &str, args: &[(&str, String)]) -> String {
    let template = CATALOG
        .get()
        .and_then(|c| c.get(lang))
        .and_then(|m| m.get(msgid))
        .map(String::as_str)
        .unwrap_or(msgid);
    if args.is_empty() || !template.contains('{') {
        return template.to_string();
    }
    // Single left-to-right pass: a substituted value is copied to the output and
    // never re-scanned, so a value that itself contains `{name}` (e.g. a nick like
    // "{game}") can't trigger a second substitution. An unknown `{x}` (no matching
    // arg, e.g. the literal `{ON|OFF}`) is left verbatim, as before.
    let mut out = String::with_capacity(template.len() + 16);
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let Some(rel_close) = rest[open..].find('}') else {
            break; // unbalanced '{' — emit the remainder verbatim below
        };
        let close = open + rel_close;
        let name = &rest[open + 1..close];
        match args.iter().find(|(n, _)| *n == name) {
            Some((_, val)) => out.push_str(val),
            None => out.push_str(&rest[open..=close]),
        }
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    out
}

/// Localize a reply. `t!(ctx, "english template", name = value, …)` looks the
/// template up for `ctx`'s language and fills its `{name}` placeholders. The
/// English string IS the message id, so it also reads as the source text.
#[macro_export]
macro_rules! t {
    ($ctx:expr, $msgid:literal $(,)?) => {
        $crate::render($ctx.lang(), $msgid, &[])
    };
    ($ctx:expr, $msgid:literal, $($name:ident = $val:expr),+ $(,)?) => {
        $crate::render($ctx.lang(), $msgid, &[$((stringify!($name), format!("{}", $val))),+])
    };
}

/// CLDR cardinal plural category. `one` vs `other` covers every language echo
/// ships: en/de/es (and es-ar)/pt use `one` only for n==1, while fr and pt-br
/// count 0 as singular too. A language with richer rules (Slavic `few`/`many`,
/// Arabic) would need a real rule table here — and, because the catalog is keyed
/// by the English text, English only offers one/other forms to key off, so such
/// a language can't gain extra categories without a different catalog shape.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Plural {
    One,
    Other,
}

/// Pick the plural category for `n` under `lang`'s rule.
pub fn plural_category(lang: &str, n: u64) -> Plural {
    let is_one = match lang {
        "fr" | "pt-br" => n == 0 || n == 1,
        _ => n == 1,
    };
    if is_one {
        Plural::One
    } else {
        Plural::Other
    }
}

/// Render the `one` or `other` English template for `n` under `lang`'s plural
/// rule, then substitute `{name}` args. The [`plural!`] macro wraps this for
/// service call sites; the engine and email layer (which have no `ctx`) call it
/// directly with an explicit language.
pub fn render_plural(lang: &str, n: u64, one: &str, other: &str, args: &[(&str, String)]) -> String {
    let key = match plural_category(lang, n) {
        Plural::One => one,
        Plural::Other => other,
    };
    render(lang, key, args)
}

/// Localize a count-dependent reply. Selects the `one` or `other` English
/// template by the target language's plural rule, then renders it like [`t!`].
/// Both forms are message ids, so both need a catalog entry in each language.
/// `plural!(ctx, n, one = "…{n} entry…", other = "…{n} entries…", n = n, …)`.
#[macro_export]
macro_rules! plural {
    ($ctx:expr, $n:expr, one = $one:literal, other = $other:literal $(, $name:ident = $val:expr)* $(,)?) => {
        $crate::render_plural($ctx.lang(), ($n) as u64, $one, $other, &[$((stringify!($name), format!("{}", $val))),*])
    };
}

/// The intent sink a service writes to. A service never mutates the network or
/// the store itself; it pushes normalized actions (via [`ServiceCtx::notice`]
/// and friends) that the engine drains and applies.
#[derive(Default)]
pub struct ServiceCtx {
    pub actions: Vec<NetAction>,
    // Namespaced stat counters to bump (e.g. "nickserv.register"). The engine
    // folds these into the shared registry after the command runs — so every
    // service reports its own stats through one shared pipe.
    pub stats: Vec<String>,
    // Staff-feed alerts (category, text) about what the sender just did. The
    // engine drains these to the log channel, prefixing the sender's nick/host —
    // e.g. a blocked look-alike registration attempt.
    pub alerts: Vec<(String, String)>,
    // Login-attempt outcomes for the auth audit feed. The engine drains these
    // through its own auth_report (which resolves the client's source), so a
    // module can report a reject the engine's verify path never sees — e.g. a
    // failed IDENTIFY against a cert-only account with no password verifier.
    pub auth_reports: Vec<AuthReport>,
    // The language to render this command's replies in (the sender's account
    // preference, else the network default). Set by the engine before dispatch;
    // empty means English. Read via [`ServiceCtx::lang`] / the `t!` macro.
    pub lang: String,
}

// A login-attempt outcome a module hands back for the auth audit feed.
#[derive(Default)]
pub struct AuthReport {
    pub ok: bool,
    pub account: Option<String>,
    pub mech: String,
    pub client: String,
    pub reason: Option<String>,
}

impl ServiceCtx {
    /// The language replies should render in (defaults to English).
    pub fn lang(&self) -> &str {
        if self.lang.is_empty() {
            "en"
        } else {
            &self.lang
        }
    }

    pub fn notice(&mut self, from: &str, to: &str, text: impl Into<String>) {
        // Auto-localize: a static English reply is looked up in the catalog for this
        // command's language and swapped for its translation (English/no-catalog =
        // unchanged). Interpolated messages must use the `t!` macro so their template
        // — not the already-filled-in text — is the lookup key.
        let text = render(self.lang(), &text.into(), &[]);
        self.actions.push(NetAction::Notice { from: from.to_string(), to: to.to_string(), text });
    }

    // IRCv3 standard replies from a service (`from` uid) to a client (`to` uid).
    // FAIL = the command failed; WARN = it worked but mind the caveat; NOTE =
    // informational. `command` is the command the reply relates to (or "*"),
    // `code` a machine-readable token (e.g. "ACCESS_DENIED"). Spec-aware clients
    // render the code + text; the rest get a plain notice (engine/module decide).
    pub fn fail(&mut self, from: &str, to: &str, command: &str, code: &str, text: impl Into<String>) {
        self.standard_reply(ReplyKind::Fail, from, to, command, code, text);
    }

    pub fn warn(&mut self, from: &str, to: &str, command: &str, code: &str, text: impl Into<String>) {
        self.standard_reply(ReplyKind::Warn, from, to, command, code, text);
    }

    pub fn note(&mut self, from: &str, to: &str, command: &str, code: &str, text: impl Into<String>) {
        self.standard_reply(ReplyKind::Note, from, to, command, code, text);
    }

    fn standard_reply(&mut self, kind: ReplyKind, from: &str, to: &str, command: &str, code: &str, text: impl Into<String>) {
        let text = render(self.lang(), &text.into(), &[]); // auto-localize static replies (see `notice`)
        self.actions.push(NetAction::StandardReply {
            kind,
            from: from.to_string(),
            to: to.to_string(),
            command: command.to_string(),
            code: code.to_string(),
            text,
        });
    }

    // Record a stat counter bump (namespaced, e.g. "chanserv.register"). Folded
    // into the engine's shared registry, which the gRPC Stats API exposes.
    pub fn count(&mut self, key: impl Into<String>) {
        self.stats.push(key.into());
    }

    // Send a line to the staff feed about what the sender just did. The engine
    // prefixes the sender's nick/host and routes it to the log channel.
    pub fn alert(&mut self, category: impl Into<String>, text: impl Into<String>) {
        self.alerts.push((category.into(), text.into()));
    }

    // Report a login-attempt outcome to the auth audit feed. For a reject the
    // engine's own verify path won't produce (a failed IDENTIFY against an account
    // with no password verifier), so operators see it like any other failed login.
    pub fn auth_report(&mut self, ok: bool, account: Option<&str>, mech: &str, client: &str, reason: Option<&str>) {
        self.auth_reports.push(AuthReport {
            ok,
            account: account.map(String::from),
            mech: mech.to_string(),
            client: client.to_string(),
            reason: reason.map(String::from),
        });
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

    // Look up `query` on a DICT server off the reactor and speak the result as
    // `speak_as` to `target`. Used by DictServ (direct query) and channel fantasy.
    pub fn dict_lookup(&mut self, speak_as: impl Into<String>, target: impl Into<String>, database: impl Into<String>, label: impl Into<String>, query: impl Into<String>) {
        self.actions.push(NetAction::DictLookup { speak_as: speak_as.into(), target: target.into(), database: database.into(), label: label.into(), query: query.into() });
    }

    // Stop the services process (OperServ SHUTDOWN/RESTART). The link layer exits
    // once this action is reached; `restart` exits non-zero so a supervisor
    // respawns us.
    pub fn shutdown(&mut self, restart: bool, reason: impl Into<String>) {
        self.actions.push(NetAction::Shutdown { restart, reason: reason.into() });
    }

    // Re-read config.toml and apply the reloadable settings live (OperServ REHASH).
    // The engine resolves this off the command path and notices `requester` from
    // `agent` with the outcome.
    pub fn rehash(&mut self, agent: &str, requester: &str) {
        self.actions.push(NetAction::Rehash { requester: requester.to_string(), agent: agent.to_string() });
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

    // Hand a password verify (IDENTIFY / SASL PLAIN) to the engine to finish: the
    // ~1s PBKDF2 runs off the reactor, then the engine completes it via `then`.
    pub fn defer_authenticate(&mut self, verifier: impl Into<String>, password: impl Into<String>, then: AuthThen) {
        self.actions.push(NetAction::DeferAuthenticate {
            verifier: verifier.into(),
            password: password.into(),
            then,
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

    pub fn set_ident(&mut self, uid: &str, ident: &str) {
        self.actions.push(NetAction::SetIdent {
            uid: uid.to_string(),
            ident: ident.to_string(),
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

    // Force a user out of a channel (SVSPART).
    pub fn force_part(&mut self, uid: &str, channel: &str, reason: &str) {
        self.actions.push(NetAction::ForcePart {
            uid: uid.to_string(),
            channel: channel.to_string(),
            reason: reason.to_string(),
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
    pub fn add_line(&mut self, kind: XlineKind, mask: &str, setter: &str, duration: u64, reason: &str) {
        self.actions.push(NetAction::AddLine {
            kind: kind.wire().to_string(),
            mask: mask.to_string(),
            setter: setter.to_string(),
            duration,
            reason: reason.to_string(),
        });
    }

    // Lift a network ban previously set with `add_line`.
    pub fn del_line(&mut self, kind: XlineKind, mask: &str) {
        self.actions.push(NetAction::DelLine { kind: kind.wire().to_string(), mask: mask.to_string() });
    }

    // Redact (delete) a message by `msgid` in `target` (a channel or nick), sourced
    // from pseudoclient `from`. `reason` may be empty. draft/message-redaction.
    pub fn redact(&mut self, from: &str, target: &str, msgid: &str, reason: &str) {
        self.actions.push(NetAction::Redact { from: from.to_string(), target: target.to_string(), msgid: msgid.to_string(), reason: reason.to_string() });
    }

    // Push a spam filter to the ircd's m_filter via a broadcast `METADATA * filter`.
    // `value` is the encoded filter (see `encode_filter`). m_filter accepts adds
    // this way; there is no matching metadata delete.
    pub fn filter_push(&mut self, value: String) {
        self.actions.push(NetAction::Metadata { target: "*".to_string(), key: "filter".to_string(), value });
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
    // Unix time this account was last active (coalesced); never below `ts`.
    pub last_seen: u64,
    // Whether the last-seen/online line is hidden from non-owner, non-oper viewers.
    pub hide_status: bool,
}

// One channel access-list entry (account -> level). `level` is either a legacy
// preset ("op"/"voice"/"founder") or a granular flag string (e.g. "otiv"); both
// resolve through `level_caps`.
#[derive(Debug, Clone)]
pub struct ChanAccessView {
    pub account: String,
    pub level: String,
}

// The granular channel-access flags, shared by ChanServ (channel access) and,
// via the same primitive, by GroupServ. Each letter grants a capability:
//   f full/co-founder   o auto-op        O op commands    h auto-halfop
//   v auto-voice        t topic          i invite         a modify access list
//   s channel settings  g greet shown
pub const ACCESS_FLAGS: &str = "foOhvtiasg";

/// A channel access rank, ordered lowest to highest. The derived `Ord` mirrors
/// the ircd's prefix ranks (voice < halfop < op < admin < founder), so services
/// decisions — PEACE, and merging a direct access entry with a group's — order
/// the tiers the same way the channel itself does. `Admin` is the SOP tier
/// (a protected op), distinct from a plain `Op` (AOP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Rank {
    #[default]
    None,
    Voice,
    Halfop,
    Op,
    Admin,
    Founder,
}

// The capabilities an access `level` confers (founder is layered on by callers).
#[derive(Debug, Clone, Copy, Default)]
pub struct Caps {
    pub auto: Option<&'static str>, // auto status mode on join: +qo / +ao / +o / +h / +v
    pub op: bool,                   // moderation: kick / ban / op / mode / akick
    pub topic: bool,
    pub invite: bool,
    pub access: bool, // may modify the access / flags / akick lists
    pub set: bool,    // may change channel settings
    pub greet: bool,
    pub rank: Rank, // ordered tier for PEACE comparisons (see `Rank`)
}

/// Generate a Copy bitset newtype over a letter-mapped flag enum — one that
/// provides `ALL: [Self; N]`, `letter(self) -> char` and `from_letter`. The
/// single source of the letter-based flag-set mechanics shared by [`Flags`]
/// (channel access) and [`GroupFlags`] (group membership).
macro_rules! flag_set {
    ($(#[$doc:meta])* $set:ident : $flag:ty = $int:ty) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
        pub struct $set($int);

        impl $set {
            /// Add a flag (builder style).
            pub fn with(self, f: $flag) -> Self { $set(self.0 | (1 << f as u8)) }
            /// Remove a flag.
            pub fn without(self, f: $flag) -> Self { $set(self.0 & !(1 << f as u8)) }
            /// Whether this set holds `f`.
            pub fn has(self, f: $flag) -> bool { self.0 & (1 << f as u8) != 0 }
            /// No flags held.
            pub fn is_empty(self) -> bool { self.0 == 0 }

            /// Parse a letter string, silently skipping unknown letters — lenient,
            /// for reading stored state. Use [`Self::apply_delta`] for user input.
            pub fn parse(s: &str) -> Self {
                s.chars().filter_map(<$flag>::from_letter).fold(Self::default(), Self::with)
            }

            /// Apply a `+ab-c`-style delta (bare letters grant). `Err(letter)` on the
            /// first character that isn't `+`, `-`, or a known flag.
            pub fn apply_delta(self, delta: &str) -> Result<Self, char> {
                let mut set = self;
                let mut adding = true;
                for c in delta.chars() {
                    match c {
                        '+' => adding = true,
                        '-' => adding = false,
                        _ => match <$flag>::from_letter(c) {
                            Some(f) => set = if adding { set.with(f) } else { set.without(f) },
                            None => return Err(c),
                        },
                    }
                }
                Ok(set)
            }

            /// The canonical letter string, in `ALL` order — the stored/displayed form.
            pub fn to_letters(self) -> String {
                <$flag>::ALL.into_iter().filter(|f| self.has(*f)).map(<$flag>::letter).collect()
            }
        }
    };
}

/// A single channel-access flag — typed rather than a bare char, so the compiler
/// checks every use and there's one source of truth for the letter and what it
/// grants. Stored (wire / access list) as its letter; the set is a [`Flags`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flag {
    Founder, // f — full access (founder-equivalent)
    AutoOp,  // o — auto-op on join, plus op moderation
    Op,      // O — op moderation without auto-op
    Halfop,  // h — auto-halfop
    Voice,   // v — auto-voice
    Topic,   // t — change the topic
    Invite,  // i — invite
    Access,  // a — manage the access / flags / akick lists
    Set,     // s — change channel settings
    Greet,   // g — greeting shown on join
}

impl Flag {
    /// Every flag, in canonical (display / ACCESS_FLAGS) order.
    pub const ALL: [Flag; 10] = [
        Flag::Founder, Flag::AutoOp, Flag::Op, Flag::Halfop, Flag::Voice, Flag::Topic, Flag::Invite, Flag::Access, Flag::Set, Flag::Greet,
    ];

    /// The flag's letter. Exhaustive, so a new variant forces choosing its letter.
    pub fn letter(self) -> char {
        match self {
            Flag::Founder => 'f',
            Flag::AutoOp => 'o',
            Flag::Op => 'O',
            Flag::Halfop => 'h',
            Flag::Voice => 'v',
            Flag::Topic => 't',
            Flag::Invite => 'i',
            Flag::Access => 'a',
            Flag::Set => 's',
            Flag::Greet => 'g',
        }
    }

    /// Parse a flag letter; `None` if it isn't a recognised flag.
    pub fn from_letter(c: char) -> Option<Flag> {
        Self::ALL.into_iter().find(|f| f.letter() == c)
    }
}

flag_set!(
    /// The set of channel-access flags an entry holds — the typed form of a stored
    /// flag string like "otia". Same bitset primitive as [`Privs`] / [`GroupFlags`].
    Flags: Flag = u16
);

impl Flags {
    /// The flags a stored `level` resolves to: the tier presets map to equivalent
    /// flags, anything else is parsed as a flag string. (The `founder` preset —
    /// the channel owner — is handled in `level_caps`, not here.)
    pub fn from_level(level: &str) -> Flags {
        let base = Flags::default();
        match level {
            "sop" => base.with(Flag::AutoOp).with(Flag::Topic).with(Flag::Invite).with(Flag::Access),
            "op" => base.with(Flag::AutoOp).with(Flag::Topic).with(Flag::Invite),
            "halfop" => base.with(Flag::Halfop),
            "voice" => base.with(Flag::Voice),
            "founder" => base.with(Flag::Founder),
            flags => Flags::parse(flags),
        }
    }

    /// The capabilities these flags confer.
    pub fn caps(self) -> Caps {
        let founderish = self.has(Flag::Founder);
        let autoop = self.has(Flag::AutoOp);
        let op = autoop || self.has(Flag::Op);
        let access = self.has(Flag::Access);
        // Auto-op plus access-list management is the SOP tier: auto protect + op.
        let auto = if autoop {
            if access { Some("+ao") } else { Some("+o") }
        } else if self.has(Flag::Halfop) {
            Some("+h")
        } else if self.has(Flag::Voice) {
            Some("+v")
        } else {
            None
        };
        let rank = if founderish {
            Rank::Founder
        } else if op && access {
            Rank::Admin
        } else if op {
            Rank::Op
        } else if self.has(Flag::Halfop) {
            Rank::Halfop
        } else if !self.is_empty() {
            Rank::Voice // voice, or any other privilege without a higher status mode
        } else {
            Rank::None
        };
        Caps {
            auto,
            op: founderish || op,
            topic: founderish || self.has(Flag::Topic),
            invite: founderish || self.has(Flag::Invite),
            access: founderish || access,
            set: founderish || self.has(Flag::Set),
            greet: founderish || self.has(Flag::Greet),
            rank,
        }
    }
}

// Resolve an access `level` string to its capabilities. The founder (channel
// owner) is the one level flags can't express (no owner flag), so it's explicit;
// every other level — the tier presets and raw flag strings alike — resolves
// through its `Flags` set.
pub fn level_caps(level: &str) -> Caps {
    if level == "founder" {
        return Caps { auto: Some("+qo"), op: true, topic: true, invite: true, access: true, set: true, greet: true, rank: Rank::Founder };
    }
    Flags::from_level(level).caps()
}

/// The tiered "XOP" role a stored access level resolves to. The four shortcut
/// tiers rank VOP < HOP < AOP < SOP (SOP is AOP plus access-list management);
/// the channel owner is `Founder`, and a granular FLAGS entry that lines up with
/// no tier is `Custom`. Classifying by resolved capability rather than the raw
/// level string means XOP- and FLAGS-set entries agree on which tier they are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessRole {
    Founder,
    Sop,
    Aop,
    Hop,
    Vop,
    Custom,
}

impl AccessRole {
    /// How the role reads in ALIST / STATUS output.
    pub fn label(self) -> &'static str {
        match self {
            Self::Founder => "founder",
            Self::Sop => "sop",
            Self::Aop => "op",
            Self::Hop => "halfop",
            Self::Vop => "voice",
            Self::Custom => "access",
        }
    }

    /// Parse a tier word (SOP/AOP/HOP/VOP/FOUNDER) into a role, for LEVELS.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "SOP" => Some(Self::Sop),
            "AOP" => Some(Self::Aop),
            "HOP" => Some(Self::Hop),
            "VOP" => Some(Self::Vop),
            "FOUNDER" => Some(Self::Founder),
            _ => None,
        }
    }

    /// Ordering rank for "this tier and above" comparisons (Vop < Hop < Aop < Sop
    /// < Founder). A `Custom` flag entry sits below the tiers, so tier-based LEVELS
    /// grants don't apply to it — it keeps exactly the flags it was given.
    pub fn rank(self) -> u8 {
        match self {
            Self::Custom => 0,
            Self::Vop => 1,
            Self::Hop => 2,
            Self::Aop => 3,
            Self::Sop => 4,
            Self::Founder => 5,
        }
    }

    /// The XOP command word this role is the exact tier of, if any. Founder and
    /// Custom entries belong to no XOP list.
    pub fn xop_word(self) -> Option<&'static str> {
        Some(match self {
            Self::Sop => "SOP",
            Self::Aop => "AOP",
            Self::Hop => "HOP",
            Self::Vop => "VOP",
            _ => return None,
        })
    }
}

/// A channel capability a founder can re-grant to a lower access tier with LEVELS.
/// Each maps to a boolean `Caps` field that gates real commands (op-family / topic
/// / invite / access-list management). LEVELS is additive: it only lowers the tier
/// that holds a capability, never removes one, so it can't lock anyone out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LevelCap {
    Op,     // op-family: OP/DEOP, AKICK, KICK, BAN, GETKEY, ENTRYMSG (via is_op)
    Topic,  // TOPIC
    Invite, // INVITE
    Access, // ACCESS / FLAGS / XOP list management
}

impl LevelCap {
    pub const ALL: [LevelCap; 4] = [Self::Op, Self::Topic, Self::Invite, Self::Access];

    pub fn name(self) -> &'static str {
        match self {
            Self::Op => "OP",
            Self::Topic => "TOPIC",
            Self::Invite => "INVITE",
            Self::Access => "ACCESS",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.name().eq_ignore_ascii_case(s))
    }

    /// The tier that holds this capability by default (from the XOP presets).
    pub fn default_role(self) -> AccessRole {
        match self {
            Self::Access => AccessRole::Sop,
            _ => AccessRole::Aop,
        }
    }

    fn grant(self, c: &mut Caps) {
        match self {
            Self::Op => c.op = true,
            Self::Topic => c.topic = true,
            Self::Invite => c.invite = true,
            Self::Access => c.access = true,
        }
    }
}

/// Classify a stored access `level` into its tiered role by resolved capability,
/// so a FLAGS entry lands in the same tier a XOP ADD would have given it.
pub fn access_role(level: &str) -> AccessRole {
    let c = level_caps(level);
    if c.set && c.access && c.op {
        AccessRole::Founder
    } else if c.op && c.access {
        AccessRole::Sop
    } else if c.op {
        AccessRole::Aop
    } else if c.auto == Some("+h") {
        AccessRole::Hop
    } else if c.auto == Some("+v") {
        AccessRole::Vop
    } else {
        AccessRole::Custom
    }
}

/// Build the argument for a channel MODE that applies the prefix modes in
/// `modes` (e.g. "+ao", "-aohv") to `target`. Every prefix mode takes the target
/// as its parameter, so the target is repeated once per mode letter — a single
/// "+o" gives "+o nick", "+ao" gives "+ao nick nick".
pub fn status_mode(modes: &str, target: &str) -> String {
    let letters = modes.chars().filter(|c| c.is_ascii_alphabetic()).count();
    let mut out = String::from(modes);
    for _ in 0..letters {
        out.push(' ');
        out.push_str(target);
    }
    out
}

// The granular group-membership flags (GroupServ), same primitive, different
// letters (see `GroupFlag`).
pub const GROUP_FLAGS: &str = "Fficsm";

/// A single group-membership flag (GroupServ) — the same primitive as [`Flag`]
/// with a different letter set. Stored as its letter; the set is a [`GroupFlags`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupFlag {
    Founder, // F — founder-level management
    Manage,  // f — modify the member / flags list
    Invite,  // i — invite members
    Channel, // c — inherit the group's channel access
    Set,     // s — set group options
    Memo,    // m — group memos
}

impl GroupFlag {
    /// Every flag, in canonical (display / GROUP_FLAGS) order.
    pub const ALL: [GroupFlag; 6] = [GroupFlag::Founder, GroupFlag::Manage, GroupFlag::Invite, GroupFlag::Channel, GroupFlag::Set, GroupFlag::Memo];

    /// The flag's letter. Exhaustive, so a new variant forces choosing its letter.
    pub fn letter(self) -> char {
        match self {
            GroupFlag::Founder => 'F',
            GroupFlag::Manage => 'f',
            GroupFlag::Invite => 'i',
            GroupFlag::Channel => 'c',
            GroupFlag::Set => 's',
            GroupFlag::Memo => 'm',
        }
    }

    /// Parse a flag letter; `None` if it isn't a recognised group flag.
    pub fn from_letter(c: char) -> Option<GroupFlag> {
        Self::ALL.into_iter().find(|f| f.letter() == c)
    }
}

flag_set!(
    /// The set of group-membership flags a member holds — the typed form of a
    /// stored flag string like "Fc". Same bitset primitive as [`Flags`] / [`Privs`].
    GroupFlags: GroupFlag = u8
);

impl Caps {
    // Combine two capability sets (a direct access entry and a group's), taking
    // the union of privileges, the higher rank, and the strongest auto-mode.
    pub fn union(self, other: Caps) -> Caps {
        // Strength of an auto status mode, owner > protect > op > halfop > voice,
        // robust to letter order and to combined modes like "+qo" / "+ao".
        let rank_of = |m: Option<&'static str>| {
            m.map_or(0, |s| {
                if s.contains('q') {
                    5
                } else if s.contains('a') {
                    4
                } else if s.contains('o') {
                    3
                } else if s.contains('h') {
                    2
                } else if s.contains('v') {
                    1
                } else {
                    0
                }
            })
        };
        let auto = if rank_of(self.auto) >= rank_of(other.auto) { self.auto } else { other.auto };
        Caps {
            auto,
            op: self.op || other.op,
            topic: self.topic || other.topic,
            invite: self.invite || other.invite,
            access: self.access || other.access,
            set: self.set || other.set,
            greet: self.greet || other.greet,
            rank: self.rank.max(other.rank),
        }
    }
}

// A user group (GroupServ) and its members, as a read view.
#[derive(Debug, Clone)]
pub struct GroupMemberView {
    pub account: String,
    pub flags: String,
}

#[derive(Debug, Clone)]
pub struct GroupView {
    pub name: String,
    pub founder: String,
    pub members: Vec<GroupMemberView>,
}

// One auto-kick entry (a hostmask and the reason shown on kick).
#[derive(Debug, Clone)]
pub struct ChanAkickView {
    pub mask: String,
    pub reason: String,
}

/// A live user's identity, matched against an AKICK mask (plain host or extban).
/// Built by the engine from what the ircd told us in the UID + metadata.
pub struct BanTarget<'a> {
    pub nick: &'a str,
    pub ident: &'a str,
    pub host: &'a str,     // displayed host
    pub realhost: &'a str, // real host
    pub ip: &'a str,
    pub gecos: &'a str,    // real name
    pub account: Option<&'a str>,
    pub server: &'a str,               // the user's server name (for the server extban)
    pub fingerprint: Option<&'a str>,  // TLS client-cert fingerprint (for the fingerprint extban)
    pub channels: Vec<String>,         // channels the user is in (for the channel extban)
}

/// How echo can match a user against an extban — or `Passive` when the ircd
/// advertises the extban but the s2s protocol gives echo no per-user data for it
/// (country, class, …). Passive extbans are still known and settable; the ircd
/// enforces the resulting `+b`, echo just can't proactively kick for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtKind {
    Account,     // R — the user's services account
    Unauthed,    // U — not logged in, and the hostmask matches
    Realname,    // r — the real name (gecos)
    Realmask,    // a — <hostmask>+<realname>
    Server,      // s — the user's server name
    Fingerprint, // z — the TLS client-cert fingerprint
    Channel,     // j — the user is in a matching channel
    Passive,
}

/// One InspIRCd matching-extban echo knows about, keyed by its `name` (stable) and
/// `letter` (network-configured). The full set matches this ircd's `EXTBAN=`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtBan {
    pub name: &'static str,
    pub letter: char,
    pub kind: ExtKind,
}

/// Every InspIRCd matching-extban, name + letter + how echo matches it. The
/// admin's `[extban] enabled` list picks which of these AKICK accepts.
pub const EXTBANS: &[ExtBan] = &[
    ExtBan { name: "account", letter: 'R', kind: ExtKind::Account },
    ExtBan { name: "unauthed", letter: 'U', kind: ExtKind::Unauthed },
    ExtBan { name: "realname", letter: 'r', kind: ExtKind::Realname },
    ExtBan { name: "realmask", letter: 'a', kind: ExtKind::Realmask },
    ExtBan { name: "server", letter: 's', kind: ExtKind::Server },
    ExtBan { name: "fingerprint", letter: 'z', kind: ExtKind::Fingerprint },
    ExtBan { name: "channel", letter: 'j', kind: ExtKind::Channel },
    // Recognized but data-less over s2s — settable, ircd-enforced (see ExtKind).
    ExtBan { name: "country", letter: 'G', kind: ExtKind::Passive },
    ExtBan { name: "asn", letter: 'b', kind: ExtKind::Passive },
    ExtBan { name: "class", letter: 'n', kind: ExtKind::Passive },
    ExtBan { name: "gateway", letter: 'w', kind: ExtKind::Passive },
    ExtBan { name: "bot", letter: 'B', kind: ExtKind::Passive },
    ExtBan { name: "oper", letter: 'o', kind: ExtKind::Passive },
    ExtBan { name: "opertype", letter: 'O', kind: ExtKind::Passive },
    ExtBan { name: "securitygroup", letter: 'g', kind: ExtKind::Passive },
    ExtBan { name: "score", letter: 'y', kind: ExtKind::Passive },
    ExtBan { name: "team", letter: 't', kind: ExtKind::Passive },
    ExtBan { name: "redirect", letter: 'd', kind: ExtKind::Passive },
];

impl ExtBan {
    /// Find an extban by its name (case-insensitive) or single letter (case-
    /// sensitive: R=account, r=realname, a=realmask, s=server, …).
    pub fn lookup(token: &str) -> Option<&'static ExtBan> {
        let mut chars = token.chars();
        match (chars.next(), chars.next()) {
            (Some(c), None) => EXTBANS.iter().find(|e| e.letter == c),
            _ => EXTBANS.iter().find(|e| e.name.eq_ignore_ascii_case(token)),
        }
    }
    /// Whether echo can match a live user against this extban (has the s2s data).
    pub fn matchable(&self) -> bool {
        !matches!(self.kind, ExtKind::Passive)
    }
}

/// One extban the linked ircd actually advertises in its `CAPAB EXTBANS` burst:
/// its `name`, optional `letter`, and whether it is an acting extban (mute, …)
/// rather than a matching one. This is the authoritative live set — echo uses it
/// to accept only the extbans this ircd really offers, instead of a static guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtbanCap {
    pub name: String,
    pub letter: Option<char>,
    pub acting: bool,
}

/// How echo interprets an AKICK mask: a plain `nick!user@host` glob (`Host`), a
/// recognized extban with its value (`Ext`), or something that is neither
/// (`Unknown` — rejected at AKICK ADD).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AkickMask<'a> {
    Host(&'a str),
    Ext(&'static ExtBan, &'a str),
    Unknown(&'a str),
}

impl<'a> AkickMask<'a> {
    /// Parse a mask. An extban is `[name|letter]:value` whose name holds no `!`/`@`
    /// (so an IPv6 host in a normal mask isn't mistaken for one).
    pub fn parse(mask: &'a str) -> AkickMask<'a> {
        let Some((name, value)) = mask.split_once(':').filter(|(n, _)| !n.is_empty() && !n.contains(['!', '@'])) else {
            return AkickMask::Host(mask);
        };
        match ExtBan::lookup(name) {
            Some(eb) => AkickMask::Ext(eb, value),
            None => AkickMask::Unknown(name),
        }
    }
}

/// Whether echo leans on the ircd to enforce an akick with this `mask` (by setting
/// a channel `+b`) because it can't evaluate the mask itself: a passive extban, or
/// a matching extban the ircd offers but echo's static table doesn't know. Host
/// masks and echo's own matchable extbans return false — echo kicks those on join.
pub fn ircd_enforced(mask: &str) -> bool {
    match AkickMask::parse(mask) {
        AkickMask::Host(_) => false,
        AkickMask::Ext(eb, _) => !eb.matchable(),
        AkickMask::Unknown(_) => true,
    }
}

/// Whether an AKICK `mask` matches a live user `t` — a plain hostmask (globbed
/// against the displayed-host, real-host and IP forms, as InspIRCd's CheckBan
/// does) or a matching-extban echo has the data for. Passive/unknown never match.
pub fn akick_matches(mask: &str, t: &BanTarget) -> bool {
    let hm = |host: &str| format!("{}!{}@{}", t.nick, t.ident, host);
    let host_hit = |g: &str| glob_match(g, &hm(t.host)) || glob_match(g, &hm(t.realhost)) || glob_match(g, &hm(t.ip));
    match AkickMask::parse(mask) {
        AkickMask::Host(g) => host_hit(g),
        AkickMask::Ext(eb, v) => match eb.kind {
            ExtKind::Account => t.account.is_some_and(|a| glob_match(v, a)),
            ExtKind::Unauthed => t.account.is_none() && host_hit(v),
            ExtKind::Realname => glob_match(v, t.gecos),
            ExtKind::Realmask => v.split_once('+').is_some_and(|(h, r)| host_hit(h) && glob_match(r, t.gecos)),
            ExtKind::Server => !t.server.is_empty() && glob_match(v, t.server),
            ExtKind::Fingerprint => t.fingerprint.is_some_and(|f| glob_match(v, f)),
            ExtKind::Channel => t.channels.iter().any(|c| glob_match(v, c)),
            ExtKind::Passive => false, // ircd-enforced; echo has no data to match
        },
        AkickMask::Unknown(_) => false,
    }
}

// A memo left for an account (MemoServ).
#[derive(Debug, Clone)]
pub struct MemoView {
    pub from: String,
    pub text: String,
    pub ts: u64,
    pub read: bool,
    // The sender asked to be told when this memo is read (RSEND).
    pub receipt: bool,
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
    pub kind: XlineKind,
    pub mask: String,
    pub setter: String,
    pub reason: String,
    pub ts: u64,
    pub expires: Option<u64>,
}

// A spam filter OperServ manages and pushes to the ircd's m_filter (SPAMFILTER).
#[derive(Debug, Clone)]
pub struct FilterView {
    pub pattern: String,
    pub action: String,
    pub flags: String,
    pub reason: String,
    pub setter: String,
    pub ts: u64,
    pub expires: Option<u64>,
}

// The filter actions InspIRCd's m_filter accepts (what happens on a match).
pub const FILTER_ACTIONS: &[&str] = &["gline", "zline", "block", "silent", "kill", "shun", "warn", "none"];

// Whether `action` is a filter action m_filter understands (case-insensitive).
pub fn is_filter_action(action: &str) -> bool {
    FILTER_ACTIONS.iter().any(|a| a.eq_ignore_ascii_case(action))
}

/// Encode a filter for InspIRCd m_filter's `METADATA * filter` value:
/// `<freeform> <action> <flags> <duration> :<reason>`, spaces in the pattern
/// escaped to `\x07` exactly as m_filter's own EncodeFilter does. `flags` empty
/// becomes `-`; `duration` is seconds remaining (0 = permanent).
pub fn encode_filter(pattern: &str, action: &str, flags: &str, duration: u64, reason: &str) -> String {
    let freeform: String = pattern.chars().map(|c| if c == ' ' { '\x07' } else { c }).collect();
    let flags = if flags.is_empty() { "-" } else { flags };
    format!("{freeform} {} {flags} {duration} :{reason}", action.to_ascii_lowercase())
}

// A network-ban type OperServ manages, identified by the ircd's X-line token.
// The wire (`NetAction::AddLine`), storage, and gossip stay the string token
// (a transparent passthrough — the ircd knows more line types than we model);
// this types OperServ's own command surface so a kind can't be mistyped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XlineKind {
    Gline, // "G"    — user@host ban (AKILL)
    Qline, // "Q"    — nick ban (SQLINE)
    Rline, // "R"    — realname ban (SNLINE)
    Shun,  // "SHUN"
    Cban,  // "CBAN" — channel-name ban
}

impl XlineKind {
    /// The ircd X-line token, as stored/gossiped and sent on the wire.
    pub fn wire(self) -> &'static str {
        match self {
            Self::Gline => "G",
            Self::Qline => "Q",
            Self::Rline => "R",
            Self::Shun => "SHUN",
            Self::Cban => "CBAN",
        }
    }

    /// Parse a stored/wire token; `None` for a kind we don't model.
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "G" => Some(Self::Gline),
            "Q" => Some(Self::Qline),
            "R" => Some(Self::Rline),
            "SHUN" => Some(Self::Shun),
            "CBAN" => Some(Self::Cban),
            _ => None,
        }
    }

    /// A human label for notices/audit lines.
    pub fn label(self) -> &'static str {
        match self {
            Self::Gline => "network ban",
            Self::Qline => "nick ban",
            Self::Rline => "realname ban",
            Self::Shun => "shun",
            Self::Cban => "channel ban",
        }
    }
}

// The two InfoServ news feeds. Stored as the string token; the API is typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewsKind {
    Logon, // shown to everyone on connect
    Oper,  // staff news, shown to opers on login
}

impl NewsKind {
    pub fn wire(self) -> &'static str {
        match self {
            Self::Logon => "logon",
            Self::Oper => "oper",
        }
    }
}

// A registration-ban target for OperServ FORBID. The persistence/gossip layer
// stores the wire token (`wire()`); the Store API is typed so a call site can't
// pass a mistyped kind like "NCK" (it wouldn't compile).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForbidKind {
    Nick,
    Chan,
    Email,
}

impl ForbidKind {
    /// The stored/display token: "NICK" / "CHAN" / "EMAIL".
    pub fn wire(self) -> &'static str {
        match self {
            Self::Nick => "NICK",
            Self::Chan => "CHAN",
            Self::Email => "EMAIL",
        }
    }

    /// Parse a FORBID kind argument (case-insensitive, with common aliases).
    pub fn from_name(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "NICK" | "NICKNAME" | "ACCOUNT" => Some(Self::Nick),
            "CHAN" | "CHANNEL" => Some(Self::Chan),
            "EMAIL" | "MAIL" => Some(Self::Email),
            _ => None,
        }
    }
}

// A registration ban held by OperServ FORBID.
#[derive(Debug, Clone)]
pub struct ForbidView {
    pub kind: ForbidKind,
    pub mask: String,
    pub setter: String,
    pub reason: String,
    pub ts: u64,
}

// One OperServ NOTIFY watch entry: a mask opers want events flagged for. `flags`
// is a subset of "cdjpntsS" (connect/disconnect/join/part/nick/topic/services).
// `expires` is None for a permanent watch.
#[derive(Debug, Clone)]
pub struct NotifyView {
    pub mask: String,
    pub flags: String,
    pub reason: String,
    pub setter: String,
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

// A help-desk ticket held by HelpServ.
#[derive(Debug, Clone)]
pub struct HelpView {
    pub id: u64,
    pub requester: String,
    pub message: String,
    pub ts: u64,
    pub handler: Option<String>,
    pub open: bool,
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
    // Param values for locked param-modes (+f flood, +j joinflood), in the order
    // their mode chars appear in `lock_on`.
    pub lock_params: Vec<(char, String)>,
    pub access: Vec<ChanAccessView>,
    pub akick: Vec<ChanAkickView>,
    // LEVELS overrides: a capability granted to this access tier and above (in
    // addition to the tier's defaults). Empty = the standard XOP capabilities.
    pub levels: Vec<(LevelCap, AccessRole)>,
    pub desc: String,
    pub entrymsg: String,
    // Channel homepage URL, shown in INFO (empty = none).
    pub url: String,
    // Channel contact email, shown in INFO (empty = none).
    pub email: String,
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
    // Kick users without channel access when they join.
    Restricted,
    // Auto-op/voice access members on join (on by default).
    AutoOp,
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
    // The account's resolved capabilities, or the empty set if it holds no access.
    // The founder holds everything.
    pub fn caps_of(&self, account: Option<&str>) -> Caps {
        let Some(acc) = account else { return Caps::default() };
        if self.founder.eq_ignore_ascii_case(acc) {
            return level_caps("founder");
        }
        let Some(entry) = self.access.iter().find(|a| a.account.eq_ignore_ascii_case(acc)) else {
            return Caps::default();
        };
        let mut caps = level_caps(&entry.level);
        // Layer LEVELS grants on top: a capability the founder granted to this tier
        // (or a lower one) is added. Purely additive, so it never removes a cap.
        if !self.levels.is_empty() {
            let role = access_role(&entry.level);
            for (cap, min_role) in &self.levels {
                if role.rank() >= min_role.rank() {
                    cap.grant(&mut caps);
                }
            }
        }
        caps
    }

    // The status mode this account gets on join (+o / +h / +v), or None.
    pub fn join_mode(&self, account: &str) -> Option<&'static str> {
        self.caps_of(Some(account)).auto
    }

    // The ordered access rank used for PEACE comparisons (see `Rank`).
    pub fn access_rank(&self, account: Option<&str>) -> Rank {
        self.caps_of(account).rank
    }

    // Whether this account holds channel-operator (moderation) access.
    pub fn is_op(&self, account: &str) -> bool {
        self.caps_of(Some(account)).op
    }

    // The mode-lock rendered as an applyable mode string, e.g. "+rnt-s".
    pub fn lock_modes(&self) -> String {
        let mut s = format!("+r{}", self.lock_on);
        if !self.lock_off.is_empty() {
            s.push('-');
            s.push_str(&self.lock_off);
        }
        // Param modes take their argument as a trailing token, in mode-char order.
        for ch in self.lock_on.chars() {
            if let Some((_, param)) = self.lock_params.iter().find(|(c, _)| *c == ch) {
                s.push(' ');
                s.push_str(param);
            }
        }
        s
    }

    // The first auto-kick entry matching a live user (host mask or extban).
    pub fn akick_match(&self, target: &BanTarget) -> Option<&ChanAkickView> {
        self.akick.iter().find(|k| akick_matches(&k.mask, target))
    }
}

// When a nick was last seen, and doing what.
#[derive(Debug, Clone)]
pub struct SeenView {
    pub nick: String,
    pub ts: u64,
    pub what: String,
}

// A nick's last message in a channel (channel-scoped SEEN).
pub struct ChanSeenView {
    pub nick: String,
    pub ts: u64,
    pub msg: String,
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
    Full,       // the account's fingerprint list is at its cap
    Internal,   // persistence failed
}

#[derive(Debug)]
pub enum ChanError {
    Exists,         // channel already registered
    NoChannel,      // channel is not registered
    InvalidPattern, // a badword regex didn't compile
    Full,           // the list (access / akick) is at its cap
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
    // Whether an extban of this name may be used in AKICK (the `[extban] enabled`
    // config). The default is permissive — every extban echo knows; the live Db
    // narrows it to the configured set.
    fn extban_enabled(&self, _name: &str) -> bool {
        true
    }
    // Whether the linked ircd actually offers this extban (its CAPAB EXTBANS set).
    // Permissive by default; the live Db answers from what the ircd advertised.
    fn extban_offered(&self, _name: &str) -> bool {
        true
    }
    // Resolve an extban token (name or single letter) the ircd advertised but echo's
    // static table doesn't know, to its live-registry entry. None if not offered.
    fn extban_lookup(&self, _token: &str) -> Option<ExtbanCap> {
        None
    }
    // The ircd's live extban set (its CAPAB EXTBANS burst), for HELP to list what
    // this network actually offers. Empty until we link.
    fn extbans(&self) -> Vec<ExtbanCap> {
        Vec::new()
    }
    // Whether channel mode `m` takes a parameter (direction-aware), from the ircd's
    // advertised CHANMODES if known. Default is the static arity.
    fn chanmode_takes_param(&self, m: char, adding: bool) -> bool {
        chanmode_takes_param(m, adding)
    }
    // The channel prefix (status) mode letters the ircd advertises. Default static.
    fn status_modes(&self) -> String {
        STATUS_MODES.to_string()
    }
    fn exists(&self, name: &str) -> bool;
    fn account(&self, name: &str) -> Option<AccountView>;
    // Canonical account name for a nick (following a grouping), if registered.
    fn resolve_account(&self, name: &str) -> Option<&str>;
    /// Registered accounts whose name matches `pattern` (a glob), for oper LIST.
    fn accounts_matching(&self, pattern: &str) -> Vec<AccountView>;
    /// Names of accounts whose email matches `pattern` (a glob), for oper GETEMAIL.
    fn accounts_by_email(&self, pattern: &str) -> Vec<String>;
    // The canonical account name if the password is correct, else None.
    fn authenticate(&self, name: &str, password: &str) -> Option<&str>;
    /// The account's canonical name and its SHA-256 verifier (owned), so the
    /// caller can run the ~1s PBKDF2 verify OFF the engine lock via
    /// `ctx.defer_authenticate` rather than the blocking `authenticate`.
    fn scram_verifier(&self, name: &str) -> Option<(String, String)>;
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
    fn set_language(&mut self, account: &str, language: Option<String>) -> Result<(), RegError>;
    fn language_of(&self, account: &str) -> Option<String>;
    fn available_languages(&self) -> Vec<String>;
    fn default_language(&self) -> String;
    // NickServ SET AUTOOP: whether this account is auto-opped on join.
    fn set_account_autoop(&mut self, account: &str, on: bool) -> Result<(), RegError>;
    fn account_wants_autoop(&self, account: &str) -> bool;
    // NickServ SET KILL: whether this account's nicks are enforcer-protected.
    fn set_account_kill(&mut self, account: &str, on: bool) -> Result<(), RegError>;
    fn account_wants_protect(&self, account: &str) -> bool;
    // NickServ SET HIDE STATUS: whether this account hides its last-seen line.
    fn set_account_hide_status(&mut self, account: &str, on: bool) -> Result<(), RegError>;
    fn account_hides_status(&self, account: &str) -> bool;
    fn set_account_snotice(&mut self, account: &str, on: bool) -> Result<(), RegError>;
    fn account_wants_snotice(&self, account: &str) -> bool;
    // HostServ vhosts.
    fn set_vhost(&mut self, account: &str, host: &str, setter: &str, ttl: Option<u64>) -> Result<(), RegError>;
    fn del_vhost(&mut self, account: &str) -> Result<bool, RegError>;
    fn vhost(&self, account: &str) -> Option<VhostView>;
    fn vhosts(&self) -> Vec<VhostView>;
    fn vhost_owner(&self, host: &str) -> Option<String>;
    fn request_vhost(&mut self, account: &str, host: &str) -> Result<(), RegError>;
    fn vhost_request_wait(&self, account: &str) -> u64;
    // Seconds before another emailed code may be issued for this account (0 = now).
    fn code_issue_wait(&self, account: &str) -> u64;
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
    fn akill_add(&mut self, kind: XlineKind, mask: &str, setter: &str, reason: &str, expires: Option<u64>) -> Result<bool, RegError>;
    fn akill_del(&mut self, kind: XlineKind, mask: &str) -> Result<bool, RegError>;
    fn akills(&self) -> Vec<AkillView>;
    // Spam filters (OperServ SPAMFILTER, oper-only), persisted and re-asserted to
    // the ircd at each burst. `filter_add` returns whether it was newly added.
    fn filter_add(&mut self, pattern: &str, action: &str, flags: &str, setter: &str, reason: &str, expires: Option<u64>) -> Result<bool, RegError>;
    fn filter_del(&mut self, pattern: &str) -> Result<bool, RegError>;
    fn filters(&self) -> Vec<FilterView>;
    // Registration bans (OperServ FORBID).
    fn forbid_add(&mut self, kind: ForbidKind, mask: &str, setter: &str, reason: &str) -> Result<bool, RegError>;
    fn forbid_del(&mut self, kind: ForbidKind, mask: &str) -> Result<bool, RegError>;
    fn forbids(&self) -> Vec<ForbidView>;
    fn is_forbidden(&self, kind: ForbidKind, name: &str) -> Option<String>;
    // OperServ NOTIFY (oper watch list). `notify_flags` returns the union of the
    // flag letters of every live entry that matches the given user and/or channel,
    // for the engine to test against a specific event.
    fn notify_add(&mut self, mask: &str, flags: &str, reason: &str, setter: &str, expires: Option<u64>) -> Result<bool, RegError>;
    fn notify_del(&mut self, mask: &str) -> Result<bool, RegError>;
    fn notify_clear(&mut self) -> Result<usize, RegError>;
    fn notifies(&self) -> Vec<NotifyView>;
    fn any_notifies(&self) -> bool;
    fn notify_flags(&self, target: Option<&BanTarget>, chan: Option<&str>) -> String;
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
    // OperServ SET READONLY: operator lockdown that refuses locally-authored
    // writes. Ephemeral (resets on restart).
    fn readonly(&self) -> bool;
    fn set_readonly(&mut self, on: bool);
    fn registrations_frozen(&self) -> bool;
    fn channel_regs_frozen(&self) -> bool;
    // Whether account identity is owned externally (website); when true, IRC
    // can't register or change credentials — it only authenticates.
    fn external_accounts(&self) -> bool;
    // Whether REGISTER should reject look-alike / mixed-script names ([register]
    // confusable_check). Defaults on; a mock store need not override it.
    fn confusable_check_enabled(&self) -> bool {
        true
    }
    // Staff notes on accounts/channels (oper-only), shown in INFO to operators.
    fn set_account_note(&mut self, account: &str, note: Option<String>) -> bool;
    fn account_note(&self, account: &str) -> Option<String>;
    fn set_channel_note(&mut self, channel: &str, note: Option<String>) -> bool;
    fn channel_note(&self, channel: &str) -> Option<String>;
    // News items shown on connect (logon) / login (oper), oper-only to manage.
    fn news_add(&mut self, kind: NewsKind, text: &str, setter: &str) -> u64;
    fn news_del(&mut self, id: u64) -> bool;
    fn news(&self, kind: NewsKind) -> Vec<NewsView>;
    // Abuse reports (ReportServ). `report_file` is rate-limited (None = too soon).
    fn report_file(&mut self, reporter: &str, cooldown_key: &str, target: &str, reason: &str) -> Option<u64>;
    fn report_close(&mut self, id: u64) -> bool;
    fn report_del(&mut self, id: u64) -> bool;
    fn reports(&self, open_only: bool) -> Vec<ReportView>;
    fn report(&self, id: u64) -> Option<ReportView>;
    // Help-desk tickets (HelpServ). `help_request` is rate-limited (None = too soon).
    fn help_request(&mut self, requester: &str, cooldown_key: &str, message: &str) -> Option<u64>;
    fn help_take(&mut self, id: u64, handler: &str) -> bool;
    fn help_close(&mut self, id: u64) -> bool;
    fn help_tickets(&self, open_only: bool) -> Vec<HelpView>;
    fn help_ticket(&self, id: u64) -> Option<HelpView>;
    fn help_next_open(&self) -> Option<u64>;
    // User groups (GroupServ).
    fn group_register(&mut self, name: &str, founder: &str) -> Result<(), ChanError>;
    fn group_drop(&mut self, name: &str) -> Result<(), ChanError>;
    fn group_set_flags(&mut self, name: &str, account: &str, flags: &str) -> Result<(), ChanError>;
    fn group_del_member(&mut self, name: &str, account: &str) -> Result<bool, ChanError>;
    fn group_set_founder(&mut self, name: &str, founder: &str) -> Result<(), ChanError>;
    fn group(&self, name: &str) -> Option<GroupView>;
    fn groups(&self) -> Vec<String>;
    fn groups_of(&self, account: &str) -> Vec<String>;
    fn groups_founded(&self, account: &str) -> usize;
    // A user's effective channel capabilities (direct access unioned with groups).
    fn channel_caps(&self, channel: &str, account: &str) -> Caps;
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
    fn set_mlock(&mut self, name: &str, on: &str, off: &str, params: Vec<(char, String)>) -> Result<(), ChanError>;
    fn set_desc(&mut self, channel: &str, desc: &str) -> Result<(), ChanError>;
    fn set_url(&mut self, channel: &str, url: &str) -> Result<(), ChanError>;
    fn set_channel_email(&mut self, channel: &str, email: &str) -> Result<(), ChanError>;
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
    // BotServ AUTOASSIGN: the bot auto-assigned to newly registered channels
    // (its canonical nick if set and still present), and the setter.
    fn default_bot(&self) -> Option<String>;
    fn set_default_bot(&mut self, bot: Option<&str>) -> Result<(), ChanError>;
    // MemoServ: per-account memos (index is a 0-based position in memo_list).
    fn memo_send(&mut self, account: &str, from: &str, text: &str, receipt: bool) -> Result<(), RegError>;
    fn memo_list(&self, account: &str) -> Vec<MemoView>;
    fn memo_read(&mut self, account: &str, index: usize) -> Option<MemoView>;
    fn memo_del(&mut self, account: &str, index: usize) -> bool;
    fn unread_memos(&self, account: &str) -> usize;
    /// Recall the most recent unread memo `sender` left for `account` (true if one was).
    fn memo_cancel(&mut self, account: &str, sender: &str) -> bool;
    fn memo_ignore_add(&mut self, account: &str, target: &str) -> bool;
    fn memo_ignore_del(&mut self, account: &str, target: &str) -> bool;
    fn memo_ignores(&self, account: &str) -> Vec<String>;
    fn memo_is_ignored(&self, account: &str, sender: &str) -> bool;
    fn set_memo_notify(&mut self, account: &str, on: bool) -> bool;
    fn set_memo_limit(&mut self, account: &str, limit: Option<u32>) -> bool;
    fn memo_notify_on(&self, account: &str) -> bool;
    fn memo_limit_of(&self, account: &str) -> Option<u32>;
    /// Read-status and timestamp of the most recent memo `sender` left for `account`.
    fn memo_check(&self, account: &str, sender: &str) -> Option<(bool, u64)>;
    fn set_entrymsg(&mut self, channel: &str, msg: &str) -> Result<(), ChanError>;
    fn set_founder(&mut self, channel: &str, account: &str) -> Result<(), ChanError>;
    fn set_successor(&mut self, channel: &str, successor: Option<&str>) -> Result<(), ChanError>;
    /// Transfer channels founded by `account` to their successor, or drop them.
    /// Returns (transferred as (channel, successor), dropped channels).
    fn release_founded_channels(&mut self, account: &str) -> (Vec<(String, String)>, Vec<String>);
    fn access_add(&mut self, channel: &str, account: &str, level: &str) -> Result<(), ChanError>;
    fn access_del(&mut self, channel: &str, account: &str) -> Result<bool, ChanError>;
    fn akick_add(&mut self, channel: &str, mask: &str, reason: &str) -> Result<(), ChanError>;
    fn akick_del(&mut self, channel: &str, mask: &str) -> Result<bool, ChanError>;
    // LEVELS: grant a capability to an access tier (and above), or reset to default.
    fn level_set(&mut self, channel: &str, cap: &str, role: &str) -> Result<(), ChanError>;
    fn level_reset(&mut self, channel: &str, cap: &str) -> Result<bool, ChanError>;
}

// The live network state a service reads (never mutates directly; changes go out
// as actions on the ServiceCtx).
pub trait NetView {
    // Account names of the network's configured operators (MemoServ STAFF). The
    // default is empty; the engine's live view overrides it. Runtime OPER grants
    // are separate (Store::opers_list) — a caller unions the two.
    fn oper_accounts(&self) -> Vec<String> {
        Vec::new()
    }
    fn uid_by_nick(&self, nick: &str) -> Option<&str>;
    fn nick_of(&self, uid: &str) -> Option<&str>;
    fn host_of(&self, uid: &str) -> Option<&str>;
    // A user's real ident (username), for restoring after an `ident@host` vhost.
    fn ident_of(&self, uid: &str) -> Option<&str>;
    fn account_of(&self, uid: &str) -> Option<&str>;
    // A user's identity for extban / AKICK matching, if known.
    fn ban_target(&self, uid: &str) -> Option<BanTarget<'_>>;
    fn uids_logged_into(&self, account: &str) -> Vec<String>;
    fn channels_of(&self, uid: &str) -> Vec<String>;
    fn is_op(&self, channel: &str, uid: &str) -> bool;
    fn channel_members(&self, channel: &str) -> Vec<String>;
    fn channel_key(&self, channel: &str) -> Option<&str>;
    fn last_seen(&self, nick: &str) -> Option<SeenView>;
    fn channel_seen(&self, channel: &str, nick: &str) -> Option<ChanSeenView>;
    // BOTSTATS: (lines seen this session, top talkers by count desc).
    fn channel_activity(&self, channel: &str) -> Option<(u64, Vec<(String, u64)>)>;
    // The shared stat counters (namespaced key -> count), for StatServ.
    fn stat_counters(&self) -> Vec<(String, u64)>;
    // Session limiting: live sessions from an IP, and IPs at/over a threshold.
    fn session_count(&self, ip: &str) -> u32;
    fn sessions_over(&self, min: u32) -> Vec<(String, u32)>;
    // ChanFix: op-time scores (identity -> score, highest first) and the current
    // op count for a channel.
    fn chanfix_scores(&self, channel: &str) -> Vec<(String, u32)>;
    fn op_count(&self, channel: &str) -> usize;
    // Search the recent moderation/action incident log (newest first, capped at
    // `limit`). An empty pattern returns the most recent; otherwise matches the
    // id or a case-insensitive substring of the summary.
    fn search_incidents(&self, pattern: &str, limit: usize) -> Vec<IncidentView>;
    // The network-wide help index the engine builds from every service, so
    // HelpServ can front help for the whole network. `help_services` lists the
    // service names; `service_help` returns one service's blurb and topics.
    fn help_services(&self) -> Vec<String> {
        Vec::new()
    }
    fn service_help(&self, _service: &str) -> Option<(&'static str, &'static [HelpEntry])> {
        None
    }
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
/// A pseudo-client such as NickServ or ChanServ. Implement this, register the
/// crate in the daemon, and the engine routes a PRIVMSG addressed to the
/// service into [`Service::on_command`]. A service touches the network and the
/// store only through [`NetView`] and [`Store`].
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
    // This service's HELP catalog: its blurb and per-command topics. The engine
    // collects these into a network-wide index HelpServ can front. Empty default.
    fn help_topics(&self) -> (&'static str, &'static [HelpEntry]) {
        ("", &[])
    }
    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, store: &mut dyn Store);
}

/// True if `addr` is safe to store and to embed in an SMTP header / hand to
/// `sendmail -t`: no control characters (notably CR/LF, which would inject mail
/// headers), no spaces, a single `@` with non-empty local and domain parts, and
/// a sane length. Deliberately permissive on the charset otherwise.
pub fn valid_email(addr: &str) -> bool {
    if addr.is_empty() || addr.len() > 254 {
        return false;
    }
    if addr.chars().any(|c| c.is_control() || c == ' ') {
        return false;
    }
    let mut parts = addr.split('@');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(local), Some(domain), None) if !local.is_empty() && !domain.is_empty()
    )
}

/// True if `nick` is a syntactically valid IRC nickname safe to introduce as a
/// pseudo-client: 1–30 chars, a letter or RFC "special" first (never a digit,
/// `-`, `#`, `:`, space or control), and only nick-legal chars after. Guards the
/// operator BOT ADD/CHANGE path so a bogus `:evil`/`#chan`/spaced nick can't be
/// minted into an IntroduceUser line.
pub fn valid_nick(nick: &str) -> bool {
    let count = nick.chars().count();
    if count == 0 || count > 30 {
        return false;
    }
    const SPECIAL: &str = "[]\\`_^{|}";
    let mut chars = nick.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_alphabetic() || SPECIAL.contains(first)) {
        return false;
    }
    nick.chars().all(|c| c.is_ascii_alphanumeric() || SPECIAL.contains(c) || c == '-')
}

/// The next free guest nick: `base` + an incrementing counter, skipping any nick
/// that is currently online or registered. An enforced/logged-out rename must not
/// land on a real user or a registered nick — that would either defeat the rename
/// (the target stays put) or collide with and kill an innocent occupant. Advances
/// `seq` past whatever it returns.
pub fn next_guest_nick(base: &str, seq: &mut u32, net: &dyn NetView, store: &dyn Store) -> String {
    for _ in 0..100_000 {
        let candidate = format!("{base}{seq}");
        *seq = seq.wrapping_add(1);
        if net.uid_by_nick(&candidate).is_none() && !store.exists(&candidate) {
            return candidate;
        }
    }
    // Pathological: the whole range is taken. Fall back rather than loop forever.
    let candidate = format!("{base}{seq}");
    *seq = seq.wrapping_add(1);
    candidate
}

/// Tell `target` account they were affected by someone else's action: notice
/// every online session, or leave a memo (from `by`) if they're offline. The
/// message renders in the target's own language. No-op when the actor is the
/// target (self-service needs no notice).
#[allow(clippy::too_many_arguments)]
pub fn notify_or_memo(ctx: &mut ServiceCtx, net: &dyn NetView, store: &mut dyn Store, service: &str, by: &str, target: &str, msgid: &str, args: &[(&str, String)]) {
    // A `!group` target is not a memo-able account, and self-service needs no notice.
    if target.starts_with('!') || by.eq_ignore_ascii_case(target) {
        return;
    }
    let lang = store.language_of(target).unwrap_or_else(|| store.default_language());
    let text = render(&lang, msgid, args);
    let online = net.uids_logged_into(target);
    if online.is_empty() {
        let _ = store.memo_send(target, by, &text, false);
    } else {
        for uid in online {
            ctx.notice(service, &uid, text.clone());
        }
    }
}

// Reject a look-alike / mixed-script registration name (nick or channel): the
// impersonation trick that a message-content filter never sees at the registration
// seam. Returns a rejection reason, or None if the name is fine. Genuine
// monolingual text in any script passes — including accented French, which is
// Latin — so only three things are caught: invisible/text-direction characters,
// mixing two alphabets in one name, and an all-homoglyph name imitating Latin.
pub fn confusable_reason(name: &str) -> Option<&'static str> {
    #[derive(PartialEq, Clone, Copy)]
    enum Script {
        Latin,
        Other, // Greek/Cyrillic/Armenian/Hebrew/Arabic/CJK — one distinct non-Latin script per range
    }
    // A letter's script, coarse: Latin vs a single non-Latin bucket per range. We
    // only need "is it Latin" and "how many distinct scripts", so non-Latin ranges
    // map to distinct discriminants via the range id.
    fn script_id(cp: u32) -> Option<(Script, u8)> {
        match cp {
            0x41..=0x5A | 0x61..=0x7A | 0xC0..=0x24F => Some((Script::Latin, 0)),
            0x370..=0x3FF | 0x1F00..=0x1FFF => Some((Script::Other, 1)), // Greek (+ Greek Extended)
            0x400..=0x52F | 0x1C80..=0x1C8F | 0x2DE0..=0x2DFF | 0xA640..=0xA69F => Some((Script::Other, 2)), // Cyrillic (+ Supplement/Extended)
            0x530..=0x58F => Some((Script::Other, 3)), // Armenian
            0x590..=0x5FF => Some((Script::Other, 4)), // Hebrew
            0x600..=0x6FF => Some((Script::Other, 5)), // Arabic
            0x4E00..=0x9FFF | 0x3040..=0x30FF => Some((Script::Other, 6)), // CJK
            _ => None,
        }
    }
    // Invisible / zero-width / bidi-control characters: no legitimate use in a name,
    // and a classic way to hide a spoof or reverse how a name renders.
    fn is_invisible(cp: u32) -> bool {
        matches!(cp, 0xAD | 0x180E | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060 | 0x2066..=0x2069 | 0xFEFF)
    }
    // "Styled" Latin that renders as normal-looking ASCII: fullwidth (Ａｄｍｉｎ),
    // mathematical alphanumerics (𝐚𝐝𝐦𝐢𝐧), and enclosed/circled/squared letters.
    // Nobody types a whole name this way except to imitate one.
    fn is_fancy_latin(cp: u32) -> bool {
        matches!(cp, 0xFF21..=0xFF5A | 0x1D400..=0x1D7FF | 0x1F130..=0x1F189 | 0x24B6..=0x24E9 | 0x2460..=0x24FF)
    }
    // Non-Latin letters that look like an ASCII Latin letter — the homoglyphs a
    // spoofer swaps in. Catches an all-look-alike name that pure script-mixing
    // would miss (e.g. an entirely-Cyrillic name that reads as Latin).
    fn is_latin_confusable(cp: u32) -> bool {
        matches!(cp,
            0x0430 | 0x0410 | 0x0435 | 0x0415 | 0x043E | 0x041E | 0x0440 | 0x0420 |
            0x0441 | 0x0421 | 0x0443 | 0x0423 | 0x0445 | 0x0425 | 0x0456 | 0x0406 |
            0x0455 | 0x0405 | 0x0458 | 0x0408 | 0x043A | 0x041A | 0x043C | 0x041C |
            0x043D | 0x041D | 0x0432 | 0x0412 | 0x0442 | 0x0422 |
            0x03BF | 0x039F | 0x03B1 | 0x0391 | 0x03B5 | 0x0395 | 0x03C1 | 0x03A1 |
            0x03C5 | 0x03A5 | 0x03BD | 0x03BA | 0x039A | 0x03B9 | 0x0399 | 0x03BC |
            0x0392 | 0x039D | 0x03A4 | 0x0397 | 0x03A7 | 0x0396)
    }

    let mut scripts: Vec<u8> = Vec::new();
    let mut has_latin = false;
    let mut letters = 0usize;
    let mut confusables = 0usize;
    for ch in name.chars() {
        let cp = ch as u32;
        if is_invisible(cp) {
            return Some("That name uses invisible or text-direction characters. Please choose a plain name.");
        }
        if is_fancy_latin(cp) {
            return Some("That name uses styled look-alike letters (fullwidth or symbol fonts). Please choose a plain name.");
        }
        if let Some((script, id)) = script_id(cp) {
            letters += 1;
            if script == Script::Latin {
                has_latin = true;
            }
            if !scripts.contains(&id) {
                scripts.push(id);
            }
            if is_latin_confusable(cp) {
                confusables += 1;
            }
        } else if ch.is_alphabetic() {
            // A letter outside every listed range (e.g. a Cyrillic Supplement
            // homoglyph, or any other non-Latin script) still counts as a distinct
            // non-Latin alphabet — so a Latin + look-alike mix is caught rather than
            // silently skipped. Monolingual text in such a script stays one bucket.
            const UNKNOWN: u8 = 99;
            letters += 1;
            if !scripts.contains(&UNKNOWN) {
                scripts.push(UNKNOWN);
            }
        }
    }
    if scripts.len() > 1 {
        return Some("That name mixes characters from different alphabets, a look-alike trick used to impersonate others. Please choose a plain name.");
    }
    // A single non-Latin script whose every letter is a Latin look-alike is a
    // homoglyph spoof even without mixing; genuine monolingual text isn't all
    // look-alikes, so it passes.
    if letters > 0 && !has_latin && confusables == letters {
        return Some("That name is made of look-alike characters imitating Latin letters. Please choose a plain name.");
    }
    None
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
    // Checked so an out-of-range duration is rejected (None) rather than wrapping to
    // a garbage/near-instant expiry in a release build.
    num.parse::<u64>().ok().and_then(|n| n.checked_mul(mult))
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

// One command's help: its name, a one-line summary shown in the command list,
// and the detail shown for `HELP <command>` (newline-separated lines).
pub struct HelpEntry {
    pub cmd: &'static str,
    pub summary: &'static str,
    pub detail: &'static str,
}

// Centralized HELP for a service: `HELP` lists the commands, `HELP <command>`
// prints that command's detail. Every service routes its HELP command here, so
// the shape is identical across every service on the network.
pub fn help(me: &str, from: &Sender, ctx: &mut ServiceCtx, blurb: &str, topics: &[HelpEntry], topic: Option<&str>) {
    let lang = ctx.lang().to_string();
    match topic {
        None => {
            ctx.notice(me, from.uid, blurb);
            for e in topics {
                // Render the summary through the catalog before interpolating, so
                // the whole formatted line doesn't need to be a catalog key.
                let summary = render(&lang, e.summary, &[]);
                ctx.notice(me, from.uid, format!("  \x02{}\x02  {}", e.cmd, summary));
            }
            ctx.notice(me, from.uid, "Type \x02HELP <command>\x02 for detail on one command.");
        }
        Some(t) => match topics.iter().find(|e| e.cmd.split('/').any(|c| c.eq_ignore_ascii_case(t))) {
            Some(e) => {
                // Render the whole (multi-line) detail, then split — the catalog
                // key is the entire detail string, not each line.
                let detail = render(&lang, e.detail, &[]);
                for line in detail.lines() {
                    ctx.notice(me, from.uid, line.to_string());
                }
            }
            None => ctx.notice(me, from.uid, render(&lang, "No help for \x02{t}\x02. Type \x02HELP\x02 for the command list.", &[("t", t.to_ascii_uppercase())])),
        },
    }
}

// Gate a command on operator privilege. `need` is the privilege required, or
// None for "any operator". Notices the user and returns false when denied,
// otherwise returns true. `what` names the action, e.g. "reviewing reports".
pub fn require_oper(me: &str, from: &Sender, ctx: &mut ServiceCtx, need: Option<Priv>, what: &str) -> bool {
    let ok = match need {
        Some(p) => from.privs.has(p),
        None => from.privs.any(),
    };
    if !ok {
        // Translate the action fragment, then the sentence around it.
        let what = render(ctx.lang(), what, &[]);
        ctx.notice(me, from.uid, render(ctx.lang(), "Access denied — {what} is for services operators.", &[("what", what)]));
    }
    ok
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
    fn confusable_names_rejected_but_french_passes() {
        // Genuine names pass — including accented French (which is Latin), other
        // monolingual scripts, digits/symbols, and emoji.
        for ok in ["Zoé", "José", "Amélie", "sœur", "Noël", "#café", "crème-brûlée", "user_42", "привет", "приве\u{0501}", "日本語", "Ελληνικά", "Zoé😀", "#général"] {
            assert!(confusable_reason(ok).is_none(), "should pass: {ok}");
        }
        // Look-alike / spoof names are rejected.
        for bad in [
            "аdmin",      // Cyrillic а + Latin — mixed script
            "a\u{0501}ice", // Latin + Cyrillic-Supplement ԁ (U+0501) — an unlisted-block homoglyph mix
            "#frее",      // Latin fr + Cyrillic ее — mixed script
            "аеосх",      // all-Cyrillic Latin look-alikes — homoglyph
            "ad\u{200b}min", // zero-width space
            "\u{202e}nimda", // right-to-left override
            "Ａｄｍｉｎ",     // fullwidth Latin
            "\u{1D41A}\u{1D41D}\u{1D426}\u{1D422}\u{1D427}", // 𝐚𝐝𝐦𝐢𝐧 mathematical bold
        ] {
            assert!(confusable_reason(bad).is_some(), "should be rejected: {bad}");
        }
    }

    #[test]
    fn akick_extbans_parse_and_match() {
        // Parse: hostmask fallback (incl IPv6), named + letter extbans, realmask
        // split, and an extban echo has no data for.
        assert_eq!(AkickMask::parse("*!*@host"), AkickMask::Host("*!*@host"));
        assert_eq!(AkickMask::parse("*!*@2001:db8::1"), AkickMask::Host("*!*@2001:db8::1"), "ipv6 host isn't an extban");
        assert!(matches!(AkickMask::parse("account:bad"), AkickMask::Ext(eb, "bad") if eb.name == "account"));
        assert!(matches!(AkickMask::parse("R:bad"), AkickMask::Ext(eb, "bad") if eb.name == "account"), "letter form");
        assert!(matches!(AkickMask::parse("realname:*spam*"), AkickMask::Ext(eb, "*spam*") if eb.name == "realname"));
        assert!(matches!(AkickMask::parse("realmask:*!*@h+*bot*"), AkickMask::Ext(eb, "*!*@h+*bot*") if eb.name == "realmask"));
        // A passive extban (echo has no per-user data for it) still parses as a
        // known extban — it just never matches.
        assert!(matches!(AkickMask::parse("country:US"), AkickMask::Ext(eb, "US") if eb.name == "country"));
        assert!(matches!(AkickMask::parse("nonsense:x"), AkickMask::Unknown("nonsense")));

        let t = BanTarget {
            nick: "n",
            ident: "u",
            host: "h.com",
            realhost: "real.h",
            ip: "1.2.3.4",
            gecos: "a spammer",
            account: Some("bad"),
            server: "irc.test",
            fingerprint: Some("deadbeef"),
            channels: vec!["#spam".to_string()],
        };
        assert!(akick_matches("*!*@h.com", &t), "displayed host");
        assert!(akick_matches("*!*@real.h", &t), "real host too");
        assert!(akick_matches("*!*@1.2.3.4", &t), "ip too");
        assert!(akick_matches("account:bad", &t));
        assert!(!akick_matches("account:other", &t));
        assert!(akick_matches("realname:*spammer*", &t), "gecos");
        assert!(akick_matches("realmask:*!*@h.com+*spammer*", &t), "host + realname");
        assert!(!akick_matches("realmask:*!*@nope+*spammer*", &t), "host part must also match");
        assert!(!akick_matches("unauthed:*!*@h.com", &t), "logged-in user isn't unauthed");
        assert!(akick_matches("server:irc.test", &t), "server name");
        assert!(akick_matches("fingerprint:deadbeef", &t), "tls fingerprint");
        assert!(akick_matches("channel:#spam", &t), "shares a banned channel");
        assert!(!akick_matches("channel:#clean", &t));
        assert!(!akick_matches("country:US", &t), "passive extban never matches");

        let anon = BanTarget { account: None, ..t };
        assert!(akick_matches("unauthed:*!*@h.com", &anon), "not logged in + host matches");
        assert!(!akick_matches("account:bad", &anon), "no account -> account extban can't match");

        // ircd_enforced: host masks and echo's matchable extbans are echo's job;
        // passive extbans and ones echo's table doesn't know are the ircd's (a +b).
        assert!(!ircd_enforced("*!*@host"), "host mask: echo kicks");
        assert!(!ircd_enforced("account:bad"), "matchable extban: echo kicks");
        assert!(ircd_enforced("country:US"), "passive extban: ircd enforces");
        assert!(ircd_enforced("mute:*!*@x"), "extban echo's table lacks: ircd enforces");
    }

    #[test]
    fn encode_filter_matches_m_filter_wire_form() {
        // "<freeform> <action> <flags> <duration> :<reason>", spaces in the pattern
        // escaped to \x07, action lowercased, empty flags -> "-".
        assert_eq!(encode_filter("*viagra*", "GLINE", "*", 0, "spam"), "*viagra* gline * 0 :spam");
        assert_eq!(encode_filter("buy now", "block", "", 3600, "ads"), "buy\x07now block - 3600 :ads");
        assert!(is_filter_action("gline") && is_filter_action("Kill") && !is_filter_action("nonsense"));
    }

    #[test]
    fn flags_bitset_parses_applies_and_matches_presets() {
        // ACCESS_FLAGS is exactly the flag letters in order — one source of truth.
        assert_eq!(ACCESS_FLAGS, Flag::ALL.iter().map(|f| f.letter()).collect::<String>());
        // Letters parse (unknown skipped) and re-emit in canonical order.
        assert_eq!(Flags::parse("aiot").to_letters(), "otia");
        assert_eq!(Flags::parse("oxz").to_letters(), "o", "unknown letters skipped");
        // Deltas: bare grants, +/- toggle, unknown letter is an error (not silent).
        assert_eq!(Flags::default().apply_delta("+ov").unwrap().to_letters(), "ov");
        assert_eq!(Flags::parse("ov").apply_delta("-o").unwrap().to_letters(), "v");
        assert_eq!(Flags::default().apply_delta("+ox"), Err('x'));
        // A preset and its flag form are interchangeable (round-trip, same caps).
        assert_eq!(Flags::from_level("sop").to_letters(), "otia");
        assert_eq!(Flags::from_level("sop").caps().rank, Rank::Admin);
        assert_eq!(Flags::from_level("halfop").to_letters(), "h");
        assert_eq!(Flags::from_level("oa").caps().auto, Some("+ao"), "op+access = protected admin");

        // Group flags are the same primitive (the macro-generated bitset); GROUP_FLAGS
        // stays in sync with the enum and deltas apply the same way.
        assert_eq!(GROUP_FLAGS, GroupFlag::ALL.iter().map(|f| f.letter()).collect::<String>());
        assert_eq!(GroupFlags::parse("cF").to_letters(), "Fc", "canonical order");
        assert!(GroupFlags::parse("Fc").has(GroupFlag::Channel));
        assert_eq!(GroupFlags::default().apply_delta("+cm").unwrap().to_letters(), "cm");
        assert_eq!(GroupFlags::default().apply_delta("+cz"), Err('z'));
    }

    #[test]
    fn access_flags_apply_and_resolve() {
        // Legacy presets and flag strings both resolve to capabilities.
        assert_eq!(level_caps("op").auto, Some("+o"));
        assert!(level_caps("op").op && level_caps("op").topic);
        assert_eq!(level_caps("voice").auto, Some("+v"));
        assert_eq!(level_caps("o").auto, Some("+o"));
        assert_eq!(level_caps("v").auto, Some("+v"));
        assert_eq!(level_caps("h").auto, Some("+h"));
        let t = level_caps("t"); // topic-only: can topic, not op
        assert!(t.topic && !t.op && t.auto.is_none());
        assert!(level_caps("a").access && level_caps("f").set);

        // Each op-and-above tier carries op (+o) plus its rank marker, so all show
        // @: founder +qo (~@), SOP +ao (&@), AOP +o (@), HOP +h.
        assert!(level_caps("sop").op && level_caps("sop").access);
        assert_eq!(level_caps("founder").auto, Some("+qo"));
        assert_eq!(level_caps("sop").auto, Some("+ao"), "SOP is op + protect");
        assert_eq!(level_caps("op").auto, Some("+o"));
        assert!(level_caps("op").op && !level_caps("op").access);
        assert_eq!(level_caps("halfop").auto, Some("+h"));

        // Combined, the stronger auto mode wins: SOP (+ao) over a voice group (+v),
        // and founder (+qo) over everything.
        assert_eq!(level_caps("sop").union(level_caps("voice")).auto, Some("+ao"));
        assert_eq!(level_caps("founder").union(level_caps("sop")).auto, Some("+qo"));

        // The FLAGS display maps presets to flag letters that round-trip: the flag
        // string resolves to the very same caps (op+access "oa" = the SOP tier,
        // auto +ao), so FLAGS-editing a preset entry can't corrupt it.
        for (preset, flags) in [("sop", "otia"), ("op", "oti"), ("halfop", "h"), ("voice", "v")] {
            assert_eq!(level_caps(flags).auto, level_caps(preset).auto, "{preset} auto");
            assert_eq!(level_caps(flags).rank, level_caps(preset).rank, "{preset} rank");
        }
        assert_eq!(level_caps("oa").auto, Some("+ao"), "op + access = protected admin");
    }

    #[test]
    fn status_mode_repeats_the_target_per_letter() {
        assert_eq!(status_mode("+o", "X"), "+o X");
        assert_eq!(status_mode("+ao", "X"), "+ao X X", "protect + op each take the nick");
        // DOWN strips the whole ladder, so the target repeats once per letter.
        assert_eq!(status_mode("-qaohv", "X"), "-qaohv X X X X X");
    }

    #[test]
    fn access_role_classifies_each_tier_by_capability() {
        // Presets round-trip to their own tier...
        assert_eq!(access_role("sop"), AccessRole::Sop);
        assert_eq!(access_role("op"), AccessRole::Aop);
        assert_eq!(access_role("halfop"), AccessRole::Hop);
        assert_eq!(access_role("voice"), AccessRole::Vop);
        assert_eq!(access_role("founder"), AccessRole::Founder);
        // ...and a granular FLAGS entry lands in the matching tier, so it lists
        // under the same XOP shortcut a tier ADD would have used.
        assert_eq!(access_role("otia"), AccessRole::Sop, "op + access = SOP");
        assert_eq!(access_role("oti"), AccessRole::Aop, "op without access = AOP");
        assert_eq!(access_role("v"), AccessRole::Vop);
        assert_eq!(access_role("ti"), AccessRole::Custom, "no status mode = no XOP tier");
        assert_eq!(access_role("sop").xop_word(), Some("SOP"));
        assert_eq!(access_role("founder").xop_word(), None);
    }

    #[test]
    fn privs_are_tiered_and_imply_the_lower_ones() {
        let admin = Privs::default().with(Priv::Admin);
        // Admin is a tier: it can exercise the lower privileges too.
        assert!(admin.has(Priv::Admin) && admin.has(Priv::Suspend) && admin.has(Priv::Oper) && admin.has(Priv::Auspex));
        // but not the tier above it,
        assert!(!admin.has(Priv::Root));
        // and `contains` reports only what was granted literally (for display).
        assert!(admin.contains(Priv::Admin) && !admin.contains(Priv::Suspend));
        assert_eq!(admin.tier(), "Services Administrator");

        // An operator can moderate but not administrate; root can do everything.
        let oper = Privs::default().with(Priv::Oper);
        assert!(oper.has(Priv::Oper) && oper.has(Priv::Auspex) && !oper.has(Priv::Suspend) && !oper.has(Priv::Admin));
        assert_eq!(oper.tier(), "Services Operator");
        let root = Privs::default().with(Priv::Root);
        assert!(root.has(Priv::Root) && root.has(Priv::Admin) && root.has(Priv::Oper) && root.has(Priv::Auspex));
        assert_eq!(root.tier(), "Services Root");

        // A grant below the operator floor is labelled honestly, never as a full
        // operator: `tier` is the highest gate the set clears, not just any bit.
        let auspex = Privs::default().with(Priv::Auspex);
        assert!(auspex.has(Priv::Auspex) && !auspex.has(Priv::Oper), "auspex alone can view, not moderate");
        assert_eq!(auspex.tier(), "limited operator");
        let suspend = Privs::default().with(Priv::Suspend);
        assert!(suspend.has(Priv::Suspend) && !suspend.has(Priv::Auspex) && !suspend.has(Priv::Oper), "suspend is a side power, not view/moderate");
        assert_eq!(suspend.tier(), "limited operator");

        assert!(!Privs::default().any(), "empty set is not an oper");
    }

    #[test]
    fn parse_names_reports_typos_instead_of_dropping_them() {
        // Known names are parsed (case-insensitive); unknown ones are collected so
        // a config typo is surfaced, not silently ignored. "root" is a real priv now.
        let (privs, unknown) = Privs::parse_names(&["Admin", "auspex", "admn", "root"]);
        assert!(privs.contains(Priv::Admin) && privs.contains(Priv::Auspex) && privs.contains(Priv::Root));
        assert_eq!(unknown, vec!["admn".to_string()]);
        assert_eq!(Priv::from_name("SUSPEND"), Some(Priv::Suspend));
        assert_eq!(Priv::from_name("administrator"), Some(Priv::Admin)); // tier alias
        assert_eq!(Priv::from_name("nope"), None);
        assert_eq!(Priv::valid_names(), "auspex, oper, suspend, admin, root");
    }

    #[test]
    fn forbid_kind_parses_aliases_and_round_trips_its_wire_token() {
        assert_eq!(ForbidKind::from_name("nickname"), Some(ForbidKind::Nick));
        assert_eq!(ForbidKind::from_name("ACCOUNT"), Some(ForbidKind::Nick));
        assert_eq!(ForbidKind::from_name("channel"), Some(ForbidKind::Chan));
        assert_eq!(ForbidKind::from_name("mail"), Some(ForbidKind::Email));
        assert_eq!(ForbidKind::from_name("nope"), None);
        // The wire token is the stable persisted/gossiped form.
        assert_eq!(ForbidKind::Nick.wire(), "NICK");
        assert_eq!(ForbidKind::from_name(ForbidKind::Email.wire()), Some(ForbidKind::Email));
    }
}

#[cfg(test)]
mod help_tests {
    use super::*;

    fn texts(ctx: &ServiceCtx) -> Vec<String> {
        ctx.actions
            .iter()
            .filter_map(|a| match a {
                NetAction::Notice { text, .. } => Some(text.clone()),
                _ => None,
            })
            .collect()
    }

    const T: &[HelpEntry] = &[
        HelpEntry { cmd: "REGISTER", summary: "register your nick", detail: "Syntax: REGISTER <password>\nRegisters your nick." },
        HelpEntry { cmd: "OP/DEOP", summary: "give or take op", detail: "Syntax: OP <#chan>\nGives or takes op." },
    ];

    fn sender<'a>() -> Sender<'a> {
        Sender { uid: "u1", nick: "nick", account: None, privs: Privs::default() }
    }

    #[test]
    fn overview_lists_every_command() {
        let mut ctx = ServiceCtx::default();
        help("Svc", &sender(), &mut ctx, "the blurb", T, None);
        let t = texts(&ctx);
        assert_eq!(t[0], "the blurb");
        assert!(t.iter().any(|l| l.contains("REGISTER") && l.contains("register your nick")));
        assert!(t.iter().any(|l| l.contains("OP/DEOP")));
        assert!(t.last().unwrap().contains("HELP <command>"));
    }

    #[test]
    fn topic_shows_detail_lines_only() {
        let mut ctx = ServiceCtx::default();
        help("Svc", &sender(), &mut ctx, "the blurb", T, Some("register"));
        let t = texts(&ctx);
        assert!(t[0].contains("Syntax: REGISTER"));
        assert!(t.iter().any(|l| l == "Registers your nick."));
        assert!(!t.iter().any(|l| l == "the blurb"));
    }

    #[test]
    fn topic_matches_a_slash_alias() {
        let mut ctx = ServiceCtx::default();
        help("Svc", &sender(), &mut ctx, "b", T, Some("DEOP"));
        assert!(texts(&ctx)[0].contains("Syntax: OP"));
    }

    #[test]
    fn unknown_topic_reports_no_help() {
        let mut ctx = ServiceCtx::default();
        help("Svc", &sender(), &mut ctx, "b", T, Some("nope"));
        assert!(texts(&ctx)[0].contains("No help"));
    }

    #[test]
    fn render_translates_substitutes_and_falls_back() {
        // No/other catalog: the English msgid is used, with args substituted.
        assert_eq!(render("en", "Hello \x02{name}\x02!", &[("name", "world".into())]), "Hello \x02world\x02!");
        // Load a French catalog, then translate + substitute.
        let mut fr = std::collections::HashMap::new();
        fr.insert("Your language is now \x02{lang}\x02.".to_string(), "Votre langue est désormais \x02{lang}\x02.".to_string());
        load_catalog(std::collections::HashMap::from([("fr".to_string(), fr)]));
        assert_eq!(
            render("fr", "Your language is now \x02{lang}\x02.", &[("lang", "fr".into())]),
            "Votre langue est désormais \x02fr\x02."
        );
        // An untranslated id still falls back to the English source even in fr.
        assert_eq!(render("fr", "not translated", &[]), "not translated");
    }

    #[test]
    fn plural_rules_match_cldr() {
        use Plural::{One, Other};
        // Most languages: singular only for exactly 1.
        for lang in ["en", "de", "es", "es-ar", "pt"] {
            assert_eq!(plural_category(lang, 1), One, "{lang} 1");
            assert_eq!(plural_category(lang, 0), Other, "{lang} 0");
            assert_eq!(plural_category(lang, 2), Other, "{lang} 2");
        }
        // French and Brazilian Portuguese count 0 as singular.
        for lang in ["fr", "pt-br"] {
            assert_eq!(plural_category(lang, 0), One, "{lang} 0");
            assert_eq!(plural_category(lang, 1), One, "{lang} 1");
            assert_eq!(plural_category(lang, 2), Other, "{lang} 2");
        }
        // Unknown language falls back to the n==1 rule.
        assert_eq!(plural_category("xx", 1), One);
        assert_eq!(plural_category("xx", 5), Other);
    }

    #[test]
    fn valid_email_rejects_header_injection() {
        assert!(valid_email("alice@example.com"));
        assert!(valid_email("a.b+c@sub.domain.co.uk"));
        // CR/LF (SMTP header injection), spaces and other controls are rejected.
        assert!(!valid_email("victim@example.com\r\nBcc: attacker@evil.com"));
        assert!(!valid_email("victim@example.com\nBcc: x@evil.com"));
        assert!(!valid_email("a b@example.com"));
        assert!(!valid_email("bad\temail@example.com"));
        // Structural nonsense is rejected too.
        assert!(!valid_email(""));
        assert!(!valid_email("no-at-sign"));
        assert!(!valid_email("two@at@signs.com"));
        assert!(!valid_email("@nolocal.com"));
        assert!(!valid_email("nodomain@"));
    }

    #[test]
    fn valid_nick_guards_bot_names() {
        assert!(valid_nick("Bendy"));
        assert!(valid_nick("Guest12345"));
        assert!(valid_nick("a-b_c`"));
        assert!(valid_nick("[bot]"));
        // Protocol-hostile or malformed nicks are rejected.
        assert!(!valid_nick(":evil")); // colon would open a trailing param
        assert!(!valid_nick("#chan"));
        assert!(!valid_nick("has space"));
        assert!(!valid_nick("bad\x02ctrl"));
        assert!(!valid_nick("1leading"));
        assert!(!valid_nick("-leading"));
        assert!(!valid_nick(""));
        assert!(!valid_nick(&"x".repeat(31)));
    }
}
