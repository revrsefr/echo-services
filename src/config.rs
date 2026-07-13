use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub uplink: Uplink,
    pub server: Server,
    // Node-to-node replication. Absent = single node, no gossip.
    #[serde(default)]
    pub gossip: Option<Gossip>,
    #[serde(default)]
    pub peer: Vec<Peer>,
    // Outbound email (password resets). Absent = email features are off.
    #[serde(default)]
    pub email: Option<Email>,
    // Directory replication (gRPC), for websites mirroring the account/channel
    // directory. Absent = the RPC server does not start.
    #[serde(default)]
    pub grpc: Option<Grpc>,
    // JSON-RPC stats endpoint (plain HTTP+JSON) for a website's stats pages.
    // Absent = it does not start. Bind to localhost; a token is required.
    #[serde(default)]
    pub jsonrpc: Option<JsonRpc>,
    // Which service modules to start. Absent = the built-in NickServ + ChanServ.
    #[serde(default)]
    pub modules: Modules,
    // Services operators: accounts granted privileges. Absent = no opers.
    #[serde(default)]
    pub oper: Vec<Oper>,
}

// One services operator: an account and the privileges it holds.
#[derive(Debug, Deserialize, Clone)]
pub struct Oper {
    pub account: String,
    #[serde(default)]
    pub privs: Vec<String>, // "auspex" | "suspend" | "admin"
}

impl Config {
    // The account -> privileges table (casefolded keys) built from [[oper]].
    pub fn opers(&self) -> std::collections::HashMap<String, fedserv_api::Privs> {
        use fedserv_api::{Priv, Privs};
        let mut map = std::collections::HashMap::new();
        for o in &self.oper {
            let mut privs = Privs::default();
            for p in &o.privs {
                match p.to_ascii_lowercase().as_str() {
                    "auspex" => privs = privs.with(Priv::Auspex),
                    "suspend" => privs = privs.with(Priv::Suspend),
                    "admin" => privs = privs.with(Priv::Admin),
                    other => tracing::warn!(privilege = other, account = %o.account, "unknown oper privilege, ignoring"),
                }
            }
            map.insert(o.account.to_ascii_lowercase(), privs);
        }
        map
    }
}

// The service modules to bring up at burst. Each name maps to a compiled-in
// module crate the daemon knows how to construct (see main.rs). Names not built
// in are ignored.
#[derive(Debug, Deserialize)]
pub struct Modules {
    #[serde(default = "default_services")]
    pub services: Vec<String>,
}

impl Default for Modules {
    fn default() -> Self {
        Modules { services: default_services() }
    }
}

fn default_services() -> Vec<String> {
    vec!["nickserv".to_string(), "chanserv".to_string(), "botserv".to_string(), "memoserv".to_string(), "statserv".to_string()]
}

#[derive(Debug, Deserialize, Clone)]
pub struct Grpc {
    // Address to accept client connections on, e.g. "127.0.0.1:50051".
    pub bind: String,
    // Bearer token every RPC must present (`authorization: Bearer <token>`).
    pub token: String,
    // Optional server-side TLS (no client cert required, unlike gossip's mTLS —
    // a subscriber is a website backend, not a federation peer).
    #[serde(default)]
    pub tls: Option<ServerTls>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerTls {
    pub cert: String, // certificate chain (PEM)
    pub key: String,  // private key (PEM)
}

#[derive(Debug, Deserialize, Clone)]
pub struct JsonRpc {
    // Address to accept HTTP on, e.g. "127.0.0.1:5601". Keep it on localhost and
    // let a reverse proxy terminate TLS / HTTP-2 / HTTP-3.
    pub bind: String,
    // Bearer token every request must present (`authorization: Bearer <token>`).
    pub token: String,
    // Browser origins allowed to call this cross-site (CORS), e.g.
    // ["https://tchatou.fr", "https://swaygo.fr"]. Empty = no browser access.
    #[serde(default)]
    pub origins: Vec<String>,
    // Terminate TLS here (enabling HTTP/2). Absent = plain HTTP, for when a
    // reverse proxy does TLS. Reuses the same cert/key shape as [grpc].
    #[serde(default)]
    pub tls: Option<ServerTls>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Email {
    // Sender address stamped on outgoing mail.
    pub from: String,
    // A shell command the message is piped to on stdin, e.g. "sendmail -t" or
    // "msmtp -t". Run via `sh -c`, so redirection and pipes work.
    pub command: String,
    // Display name shown in email templates (header/footer).
    #[serde(default = "default_brand")]
    pub brand: String,
    // Accent colour (any CSS colour) for the email template.
    #[serde(default = "default_accent")]
    pub accent: String,
    // Optional logo image URL shown in the email header (must be a hosted image;
    // email clients don't render inline SVG or data URIs).
    #[serde(default)]
    pub logo: String,
}

fn default_brand() -> String {
    "Network Services".to_string()
}

fn default_accent() -> String {
    "#4f46e5".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct Gossip {
    // Address to accept peer connections on. Absent = dial-only node.
    pub bind: Option<String>,
    // Shared secret both nodes must present.
    pub secret: String,
    // Mutual-TLS for the peer link. Absent = plaintext.
    #[serde(default)]
    pub tls: Option<Tls>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Tls {
    pub cert: String, // our certificate chain (PEM)
    pub key: String,  // our private key (PEM)
    pub ca: String,   // CA bundle that must have signed a peer's certificate (PEM)
}

#[derive(Debug, Deserialize, Clone)]
pub struct Peer {
    pub addr: String,
    // TLS server name to expect from this peer; must match its certificate.
    #[serde(default = "default_peer_name")]
    pub name: String,
}

fn default_peer_name() -> String {
    "fedserv".to_string()
}

#[derive(Debug, Deserialize)]
pub struct Uplink {
    pub host: String,
    pub port: u16,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct Server {
    pub name: String,
    pub sid: String,
    pub description: String,
    #[serde(default = "default_protocol")]
    pub protocol: u32,
    // PBKDF2 cost baked into new SCRAM verifiers at registration. High by
    // default for offline-attack resistance; lower it if registration latency
    // on the single-threaded link matters more than verifier strength.
    #[serde(default = "default_scram_iterations")]
    pub scram_iterations: u32,
    // Nick prefix a user is renamed to on NickServ LOGOUT (they keep the ircd's
    // guest number appended, e.g. Guest12345). Must start with a letter — the
    // ircd rejects a digit-leading SVSNICK and falls back to the raw uuid.
    #[serde(default = "default_guest_nick")]
    pub guest_nick: String,
}

fn default_protocol() -> u32 {
    1206 // InspIRCd 4 spanning-tree protocol (1205 = insp3)
}

fn default_guest_nick() -> String {
    "Guest".to_string()
}

fn default_scram_iterations() -> u32 {
    crate::engine::scram::DEFAULT_ITERATIONS
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&raw)?)
    }
}
