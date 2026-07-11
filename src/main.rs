mod config;
mod engine;
mod link;
mod proto;
mod services;

use anyhow::Result;
use std::time::{SystemTime, UNIX_EPOCH};

use engine::Engine;
use proto::inspircd::InspIrcd;
use services::nickserv::NickServ;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "fedserv=debug".into()),
        )
        .init();

    let path = std::env::args().nth(1).unwrap_or_else(|| "config.toml".to_string());
    let cfg = config::Config::load(&path)?;
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    let proto = Box::new(InspIrcd::new(
        cfg.server.name.clone(),
        cfg.server.sid.clone(),
        cfg.uplink.password.clone(),
        cfg.server.protocol,
        ts,
    ));

    let services: Vec<Box<dyn engine::service::Service>> = vec![Box::new(NickServ {
        uid: format!("{}AAAAAA", cfg.server.sid),
    })];
    let engine = Engine::new(services);

    let addr = format!("{}:{}", cfg.uplink.host, cfg.uplink.port);
    tracing::info!(server = %cfg.server.name, %addr, "linking to uplink");
    link::run(proto, engine, &addr).await
}
