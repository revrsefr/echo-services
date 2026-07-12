// Protocol abstraction. The engine only ever sees NetEvent / NetAction; raw
// server-to-server lines live entirely behind a Protocol impl. Adding another
// ircd later means one new module, engine untouched.
pub mod inspircd;

// Normalized inbound facts, translated from the uplink's raw lines.
#[derive(Debug, Clone)]
pub enum NetEvent {
    Registered,
    EndBurst,
    Ping { token: String, from: Option<String> },
    Privmsg { from: String, to: String, text: String },
    UserConnect { uid: String, nick: String, host: String },
    NickChange { uid: String, nick: String },
    // A channel was created or bursted (InspIRCd FJOIN). Subsequent single joins
    // arrive as IJOIN and are not surfaced.
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
}

// How to answer a registration once its credentials have been derived.
#[derive(Debug, Clone)]
pub enum RegReply {
    // IRCv3 account-registration relay: answer the requesting ircd.
    Relay { reqid: String, kind: String },
    // NickServ REGISTER: NOTICE the requesting user, logging them in on success.
    NickServ { agent: String, uid: String, nick: String },
}

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
