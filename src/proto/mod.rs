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
    UserConnect { uid: String, nick: String },
    Quit { uid: String },
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
    Raw(String),
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
