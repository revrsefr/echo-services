// Core lives in src/; the pseudo-clients and the ircd link are external module
// crates (fedserv-nickserv, fedserv-chanserv, fedserv-inspircd), each depending
// only on the fedserv-api SDK.
mod config;
mod engine;
mod gossip;
mod grpc;
mod jsonrpc;
mod link;
mod proto;

use anyhow::Result;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

use engine::Engine;
use fedserv_botserv::BotServ;
use fedserv_chanserv::ChanServ;
use fedserv_memoserv::MemoServ;
use fedserv_statserv::StatServ;
use fedserv_hostserv::HostServ;
use fedserv_operserv::OperServ;
use fedserv_example::ExampleServ;
use fedserv_inspircd::InspIrcd;
use fedserv_nickserv::NickServ;

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
        cfg.server.description.clone(),
        cfg.server.sid.clone(),
        cfg.uplink.password.clone(),
        cfg.server.protocol,
        ts,
    ));

    // Bring up the service modules named in [modules] (default NickServ +
    // ChanServ). Each keeps a fixed uid suffix so its identity is stable no
    // matter which others are enabled.
    let enabled = |name: &str| cfg.modules.services.iter().any(|s| s == name);
    let mut services: Vec<Box<dyn engine::service::Service>> = Vec::new();
    if enabled("nickserv") {
        services.push(Box::new(NickServ {
            uid: format!("{}AAAAAA", cfg.server.sid),
            guest_nick: cfg.server.guest_nick.clone(),
            guest_seq: (ts % 100_000) as u32,
        }));
    }
    if enabled("chanserv") {
        services.push(Box::new(ChanServ {
            uid: format!("{}AAAAAB", cfg.server.sid),
        }));
    }
    if enabled("botserv") {
        services.push(Box::new(BotServ {
            uid: format!("{}AAAAAD", cfg.server.sid),
        }));
    }
    if enabled("memoserv") {
        services.push(Box::new(MemoServ {
            uid: format!("{}AAAAAE", cfg.server.sid),
        }));
    }
    if enabled("statserv") {
        services.push(Box::new(StatServ {
            uid: format!("{}AAAAAF", cfg.server.sid),
        }));
    }
    if enabled("hostserv") {
        services.push(Box::new(HostServ {
            uid: format!("{}AAAAAG", cfg.server.sid),
        }));
    }
    if enabled("operserv") {
        services.push(Box::new(OperServ {
            uid: format!("{}AAAAAH", cfg.server.sid),
        }));
    }
    if enabled("example") {
        services.push(Box::new(ExampleServ {
            uid: format!("{}AAAAAC", cfg.server.sid),
        }));
    }
    let (gossip_tx, _) = tokio::sync::broadcast::channel::<engine::db::LogEntry>(1024);
    let mut db = engine::db::Db::open("fedserv.db.jsonl", &cfg.server.sid);
    db.scram_iterations = cfg.server.scram_iterations;
    db.set_outbound(gossip_tx.clone());
    db.set_email_enabled(cfg.email.is_some());
    if let Some(email) = &cfg.email {
        db.set_email_brand(&email.brand);
        db.set_email_accent(&email.accent);
        db.set_email_logo(&email.logo);
    }
    let engine = Arc::new(Mutex::new(Engine::new(services, db)));

    // Channel for services-initiated actions to reach the uplink (drained by the link loop).
    let (irc_tx, irc_rx) = tokio::sync::mpsc::unbounded_channel();
    engine.lock().await.set_irc_out(irc_tx);
    engine.lock().await.set_opers(cfg.opers());
    engine.lock().await.set_sid(cfg.server.sid.clone());
    engine.lock().await.set_log_channel(cfg.log.as_ref().map(|l| l.channel.clone()));
    if let Some(expire) = &cfg.expire {
        engine.lock().await.set_expiry(expire.account_ttl(), expire.channel_ttl());
    }

    if let Some(gossip) = cfg.gossip.clone() {
        tracing::info!(peers = cfg.peer.len(), "starting gossip");
        tokio::spawn(gossip::run(engine.clone(), gossip, cfg.peer.clone(), cfg.server.sid.clone(), gossip_tx.clone()));
    }

    // Directory replication for websites (Django, etc.) — subscribes to the same
    // committed-entry stream gossip does, so a website sees the account/channel
    // directory update in real time without touching IRC at all.
    if let Some(grpc_cfg) = cfg.grpc.clone() {
        tokio::spawn(grpc::run(engine.clone(), grpc_cfg, gossip_tx));
    }

    // JSON-RPC stats endpoint (plain HTTP), for a website's stats pages.
    if let Some(jsonrpc_cfg) = cfg.jsonrpc.clone() {
        tokio::spawn(jsonrpc::run(engine.clone(), jsonrpc_cfg));
    }

    // Periodically fold log churn into a snapshot when it grows past the accounts.
    {
        let engine = engine.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1800)).await;
                let mut e = engine.lock().await;
                e.expire_sweep();
                if let Err(err) = e.maybe_compact() {
                    tracing::warn!(%err, "compaction failed");
                }
            }
        });
    }

    let addr = format!("{}:{}", cfg.uplink.host, cfg.uplink.port);
    tracing::info!(server = %cfg.server.name, %addr, "linking to uplink");
    link::run(proto, engine, &addr, irc_rx, cfg.email.clone()).await
}
