mod config;
mod engine;
mod gossip;
mod link;
mod proto;
mod services;

use anyhow::Result;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

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
        guest_nick: cfg.server.guest_nick.clone(),
        guest_seq: (ts % 100_000) as u32,
    })];
    let (gossip_tx, _) = tokio::sync::broadcast::channel::<engine::db::LogEntry>(1024);
    let mut db = engine::db::Db::open("fedserv.db.jsonl", &cfg.server.sid);
    db.scram_iterations = cfg.server.scram_iterations;
    db.set_outbound(gossip_tx.clone());
    let engine = Arc::new(Mutex::new(Engine::new(services, db)));

    if let Some(gossip) = cfg.gossip.clone() {
        tracing::info!(peers = cfg.peer.len(), "starting gossip");
        tokio::spawn(gossip::run(engine.clone(), gossip, cfg.peer.clone(), cfg.server.sid.clone(), gossip_tx));
    }

    let addr = format!("{}:{}", cfg.uplink.host, cfg.uplink.port);
    tracing::info!(server = %cfg.server.name, %addr, "linking to uplink");
    link::run(proto, engine, &addr).await
}
