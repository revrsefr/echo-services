use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub uplink: Uplink,
    pub server: Server,
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
}

fn default_protocol() -> u32 {
    1206 // InspIRCd 4 spanning-tree protocol (1205 = insp3)
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
