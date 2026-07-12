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
}

#[derive(Debug, Deserialize, Clone)]
pub struct Email {
    // Sender address stamped on outgoing mail.
    pub from: String,
    // A shell command the message is piped to on stdin, e.g. "sendmail -t" or
    // "msmtp -t". Run via `sh -c`, so redirection and pipes work.
    pub command: String,
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
