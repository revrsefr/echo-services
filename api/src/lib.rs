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
    // A user was forcibly removed (KILL). Handled like a quit, except a killed
    // services bot is reintroduced rather than forgotten.
    UserKilled { uid: String },
    // A downstream server was introduced (a sourced SERVER). `parent` is the SID
    // that introduced it, so we can track the tree and cascade a hub's SQUIT.
    ServerLink { sid: String, parent: String },
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
    // SASL PLAIN: finish the SASL exchange for `client`, sourced from `agent`.
    Sasl { agent: String, client: String, account: String },
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

impl Priv {
    /// Every privilege, for iteration and validation.
    pub const ALL: [Priv; 3] = [Priv::Auspex, Priv::Suspend, Priv::Admin];

    /// This privilege's canonical name — the `[[oper]]` config token. Exhaustive,
    /// so adding a variant forces adding its name (no silent gap).
    pub fn name(self) -> &'static str {
        match self {
            Priv::Auspex => "auspex",
            Priv::Suspend => "suspend",
            Priv::Admin => "admin",
        }
    }

    /// Parse a privilege name (case-insensitive); `None` if unrecognised.
    pub fn from_name(s: &str) -> Option<Priv> {
        Self::ALL.into_iter().find(|p| s.eq_ignore_ascii_case(p.name()))
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

    // The privilege names held, for display.
    pub fn names(self) -> Vec<&'static str> {
        Priv::ALL.into_iter().filter(|p| self.has(*p)).map(Priv::name).collect()
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
}

impl ServiceCtx {
    pub fn notice(&mut self, from: &str, to: &str, text: impl Into<String>) {
        self.actions.push(NetAction::Notice {
            from: from.to_string(),
            to: to.to_string(),
            text: text.into(),
        });
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
        self.actions.push(NetAction::StandardReply {
            kind,
            from: from.to_string(),
            to: to.to_string(),
            command: command.to_string(),
            code: code.to_string(),
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

// Resolve an access `level` string to its capabilities. Recognises the legacy
// presets, then falls back to treating it as flag letters, so old op/voice
// entries and new flag entries coexist.
pub fn level_caps(level: &str) -> Caps {
    match level {
        "founder" => Caps { auto: Some("+qo"), op: true, topic: true, invite: true, access: true, set: true, greet: true, rank: Rank::Founder },
        // The XOP tiers, ordered high to low. Each op-and-above tier carries op
        // (+o, the @ prefix) plus its rank marker: founder owner (+q, ~), sop
        // protect (+a, &). So AOP and above all show @, while sop outranks aop and
        // founder outranks sop. SOP additionally holds access-list management.
        "sop" => Caps { auto: Some("+ao"), op: true, topic: true, invite: true, access: true, rank: Rank::Admin, ..Caps::default() },
        "op" => Caps { auto: Some("+o"), op: true, topic: true, invite: true, rank: Rank::Op, ..Caps::default() },
        "halfop" => Caps { auto: Some("+h"), rank: Rank::Halfop, ..Caps::default() },
        "voice" => Caps { auto: Some("+v"), rank: Rank::Voice, ..Caps::default() },
        flags => {
            let has = |c: char| flags.contains(c);
            // Auto-op plus access-list management is the SOP tier — it auto-gets
            // protect + op (+ao), so a flag entry "oa" matches the "sop" preset.
            let auto = if has('o') {
                if has('a') { Some("+ao") } else { Some("+o") }
            } else if has('h') {
                Some("+h")
            } else if has('v') {
                Some("+v")
            } else {
                None
            };
            let founderish = has('f');
            let op = has('o') || has('O');
            let rank = if founderish {
                Rank::Founder
            } else if op && has('a') {
                Rank::Admin // op plus access-list management = the SOP tier
            } else if op {
                Rank::Op
            } else if has('h') {
                Rank::Halfop
            } else if !flags.is_empty() {
                Rank::Voice // voice, or any other privilege without a higher status mode
            } else {
                Rank::None
            };
            Caps {
                auto,
                op: founderish || op,
                topic: founderish || has('t'),
                invite: founderish || has('i'),
                access: founderish || has('a'),
                set: founderish || has('s'),
                greet: founderish || has('g'),
                rank,
            }
        }
    }
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
// letters: F founder, f modify the member/flags list, i invite members, s set
// group options, c the group may be granted channel access, m group memos.
pub const GROUP_FLAGS: &str = "Fficsm";

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

// Apply a `+ov-h`-style delta to a flag string against a `valid` letter set,
// returning the new deduplicated flag string ordered by `valid`. A bare "ov"
// (no sign) grants. Returns Err with the first letter not in `valid`.
pub fn apply_flags(current: &str, delta: &str, valid: &str) -> Result<String, char> {
    let mut set: Vec<char> = current.chars().filter(|c| valid.contains(*c)).collect();
    let mut adding = true;
    for c in delta.chars() {
        match c {
            '+' => adding = true,
            '-' => adding = false,
            f if valid.contains(f) => {
                set.retain(|&x| x != f);
                if adding {
                    set.push(f);
                }
            }
            other => return Err(other),
        }
    }
    Ok(valid.chars().filter(|c| set.contains(c)).collect())
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
        self.access
            .iter()
            .find(|a| a.account.eq_ignore_ascii_case(acc))
            .map_or(Caps::default(), |a| level_caps(&a.level))
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
    // NickServ SET AUTOOP: whether this account is auto-opped on join.
    fn set_account_autoop(&mut self, account: &str, on: bool) -> Result<(), RegError>;
    fn account_wants_autoop(&self, account: &str) -> bool;
    // NickServ SET KILL: whether this account's nicks are enforcer-protected.
    fn set_account_kill(&mut self, account: &str, on: bool) -> Result<(), RegError>;
    fn account_wants_protect(&self, account: &str) -> bool;
    // NickServ SET HIDE STATUS: whether this account hides its last-seen line.
    fn set_account_hide_status(&mut self, account: &str, on: bool) -> Result<(), RegError>;
    fn account_hides_status(&self, account: &str) -> bool;
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
    // Registration bans (OperServ FORBID).
    fn forbid_add(&mut self, kind: ForbidKind, mask: &str, setter: &str, reason: &str) -> Result<bool, RegError>;
    fn forbid_del(&mut self, kind: ForbidKind, mask: &str) -> Result<bool, RegError>;
    fn forbids(&self) -> Vec<ForbidView>;
    fn is_forbidden(&self, kind: ForbidKind, name: &str) -> Option<String>;
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
    fn report_file(&mut self, reporter: &str, target: &str, reason: &str) -> Option<u64>;
    fn report_close(&mut self, id: u64) -> bool;
    fn report_del(&mut self, id: u64) -> bool;
    fn reports(&self, open_only: bool) -> Vec<ReportView>;
    fn report(&self, id: u64) -> Option<ReportView>;
    // Help-desk tickets (HelpServ). `help_request` is rate-limited (None = too soon).
    fn help_request(&mut self, requester: &str, message: &str) -> Option<u64>;
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
    fn account_of(&self, uid: &str) -> Option<&str>;
    fn uids_logged_into(&self, account: &str) -> Vec<String>;
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
    match topic {
        None => {
            ctx.notice(me, from.uid, blurb);
            for e in topics {
                ctx.notice(me, from.uid, format!("  \x02{}\x02  {}", e.cmd, e.summary));
            }
            ctx.notice(me, from.uid, "Type \x02HELP <command>\x02 for detail on one command.");
        }
        Some(t) => match topics.iter().find(|e| e.cmd.split('/').any(|c| c.eq_ignore_ascii_case(t))) {
            Some(e) => {
                for line in e.detail.lines() {
                    ctx.notice(me, from.uid, line);
                }
            }
            None => ctx.notice(me, from.uid, format!("No help for \x02{}\x02. Type \x02HELP\x02 for the command list.", t.to_ascii_uppercase())),
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
        ctx.notice(me, from.uid, format!("Access denied — {what} is for services operators."));
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
    fn access_flags_apply_and_resolve() {
        // +/- deltas, dedup, stable order, invalid flag rejected.
        assert_eq!(apply_flags("", "+ov", ACCESS_FLAGS).unwrap(), "ov");
        assert_eq!(apply_flags("ov", "-o", ACCESS_FLAGS).unwrap(), "v");
        assert_eq!(apply_flags("v", "+tv", ACCESS_FLAGS).unwrap(), "vt"); // ACCESS_FLAGS order, no dup
        assert_eq!(apply_flags("", "ai", ACCESS_FLAGS).unwrap(), "ia"); // bare letters grant
        assert_eq!(apply_flags("", "+ox", ACCESS_FLAGS), Err('x'));

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
    fn privs_bitset_grants_and_checks() {
        let p = Privs::default().with(Priv::Auspex).with(Priv::Admin);
        assert!(p.has(Priv::Auspex) && p.has(Priv::Admin));
        assert!(!p.has(Priv::Suspend), "only granted privileges are held");
        assert!(p.any());
        assert!(!Privs::default().any(), "empty set is not an oper");
    }

    #[test]
    fn parse_names_reports_typos_instead_of_dropping_them() {
        // Known names are parsed (case-insensitive); unknown ones are collected so
        // a config typo is surfaced, not silently ignored.
        let (privs, unknown) = Privs::parse_names(&["Admin", "auspex", "admn", "root"]);
        assert!(privs.has(Priv::Admin) && privs.has(Priv::Auspex));
        assert!(!privs.has(Priv::Suspend));
        assert_eq!(unknown, vec!["admn".to_string(), "root".to_string()]);
        assert_eq!(Priv::from_name("SUSPEND"), Some(Priv::Suspend));
        assert_eq!(Priv::from_name("nope"), None);
        assert_eq!(Priv::valid_names(), "auspex, suspend, admin");
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
}
