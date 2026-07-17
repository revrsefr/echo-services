// Core lives in src/; the pseudo-clients and the ircd link are external module
// crates (echo-nickserv, echo-chanserv, echo-inspircd), each depending
// only on the echo-api SDK.
mod config;
mod engine;
mod gossip;
mod grpc;
mod jsonrpc;
mod keycard;
mod link;
mod migrate;
mod proto;

use anyhow::Result;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

use engine::Engine;
use echo_botserv::BotServ;
use echo_chanserv::ChanServ;
use echo_memoserv::MemoServ;
use echo_statserv::StatServ;
use echo_hostserv::HostServ;
use echo_operserv::OperServ;
use echo_diceserv::DiceServ;
use echo_gameserv::GameServ;
use echo_infoserv::InfoServ;
use echo_reportserv::ReportServ;
use echo_groupserv::GroupServ;
use echo_chanfix::ChanFix;
use echo_helpserv::HelpServ;
use echo_example::ExampleServ;
use echo_inspircd::InspIrcd;
use echo_nickserv::NickServ;
use echo_debugserv::DebugServ;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                // info by default: the link layer debug-logs every raw line, which
                // includes users' identify/register passwords and SASL payloads.
                // Opt into debug explicitly (RUST_LOG=echo=debug) only when needed;
                // even then, credentials are redacted (see link::redact).
                .unwrap_or_else(|_| "echo=info".into()),
        )
        .init();

    // One-off migration: `echo import <anope.json> <out.log> [node-name]` builds a
    // fresh event log from an Anope db_json and exits, touching nothing else.
    let argv: Vec<String> = std::env::args().collect();
    if argv.get(1).map(String::as_str) == Some("import") {
        let (Some(src), Some(out)) = (argv.get(2), argv.get(3)) else {
            eprintln!("usage: echo import <anope.json> <out.log> [node-name]");
            std::process::exit(2);
        };
        let node = argv.get(4).map(String::as_str).unwrap_or("services");
        let s = migrate::import_anope(src, out, node)?;
        println!(
            "imported: {} accounts, {} grouped nicks, {} certs, {} vhosts, {} channels ({} with settings), {} access, {} mlocked, {} bots, {} memos",
            s.accounts, s.grouped_nicks, s.certs, s.vhosts, s.channels, s.settings, s.access, s.mlocked, s.bots, s.memos
        );
        for note in &s.skipped {
            println!("  skipped: {note}");
        }
        println!(
            "verified (log replays to): {} accounts, {} channels, {} bots",
            s.loaded_accounts, s.loaded_channels, s.loaded_bots
        );
        return Ok(());
    }

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
        cfg.server.service_modes.clone(),
    ));

    // Bring up the service modules named in [modules] (default: the full
    // standard suite — every pseudo-client). Each keeps a fixed uid suffix so
    // its identity is stable no matter which others are enabled.
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
    if enabled("diceserv") {
        services.push(Box::new(DiceServ {
            uid: format!("{}AAAAAI", cfg.server.sid),
        }));
    }
    if enabled("gameserv") {
        services.push(Box::new(GameServ::new(format!("{}AAAAAP", cfg.server.sid))));
    }
    if enabled("infoserv") {
        services.push(Box::new(InfoServ {
            uid: format!("{}AAAAAJ", cfg.server.sid),
        }));
    }
    if enabled("reportserv") {
        services.push(Box::new(ReportServ {
            uid: format!("{}AAAAAK", cfg.server.sid),
        }));
    }
    if enabled("groupserv") {
        services.push(Box::new(GroupServ {
            uid: format!("{}AAAAAL", cfg.server.sid),
        }));
    }
    if enabled("chanfix") {
        services.push(Box::new(ChanFix {
            uid: format!("{}AAAAAM", cfg.server.sid),
        }));
    }
    if enabled("helpserv") {
        services.push(Box::new(HelpServ {
            uid: format!("{}AAAAAN", cfg.server.sid),
        }));
    }
    if enabled("debugserv") {
        services.push(Box::new(DebugServ {
            uid: format!("{}AAAAAO", cfg.server.sid),
        }));
    }
    if enabled("example") {
        services.push(Box::new(ExampleServ {
            uid: format!("{}AAAAAC", cfg.server.sid),
        }));
    }
    let (gossip_tx, _) = tokio::sync::broadcast::channel::<engine::db::LogEntry>(1024);
    let mut db = engine::db::Db::open("echo.db.jsonl", &cfg.server.sid);
    db.scram_iterations = cfg.server.scram_iterations;
    db.set_outbound(gossip_tx.clone());
    db.set_email_enabled(cfg.email.is_some());
    db.set_external_accounts(cfg.auth.as_ref().is_some_and(|a| a.external));
    if let Some(extban) = &cfg.extban {
        db.set_extban_enabled(extban.enabled.clone());
    }
    if let Some(email) = &cfg.email {
        db.set_email_brand(&email.brand);
        db.set_email_accent(&email.accent);
        db.set_email_logo(&email.logo);
    }
    let engine = Arc::new(Mutex::new(Engine::new(services, db)));

    // Channel for services-initiated actions to reach the uplink (drained by the link loop).
    let (irc_tx, irc_rx) = tokio::sync::mpsc::unbounded_channel();
    engine.lock().await.set_irc_out(irc_tx);
    for (account, name) in cfg.oper_priv_warnings() {
        tracing::warn!(%account, privilege = %name, valid = %echo_api::Priv::valid_names(), "unknown privilege in [[oper]] — ignored (typo?)");
    }
    engine.lock().await.set_opers(cfg.opers());
    engine.lock().await.set_config_path(path.clone());
    engine.lock().await.set_sid(cfg.server.sid.clone());
    engine.lock().await.set_guest_nick(&cfg.server.guest_nick);
    // Service pseudo-clients wear the configured host, or the server name.
    let service_host = if cfg.server.service_host.is_empty() { &cfg.server.name } else { &cfg.server.service_host };
    engine.lock().await.set_service_host(service_host);
    engine.lock().await.set_service_oper_type(cfg.server.service_oper_type.clone());
    engine.lock().await.set_services_channel(cfg.server.services_channel.clone());
    engine.lock().await.set_standard_replies(cfg.server.standard_replies);
    engine.lock().await.set_log_channel(cfg.log.as_ref().map(|l| l.channel.clone()));
    if enabled("debugserv") {
        // DebugServ speaks the live feed into the log channel; give the engine its uid.
        engine.lock().await.set_debugserv_uid(format!("{}AAAAAO", cfg.server.sid));
    }
    if let Some(expire) = &cfg.expire {
        engine.lock().await.set_expiry(expire.account_ttl(), expire.channel_ttl(), expire.warn_ttl());
    }
    if let Some(session) = &cfg.session {
        engine.lock().await.set_session_limit(session.limit());
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
                tokio::time::sleep(std::time::Duration::from_secs(300)).await;
                let mut e = engine.lock().await;
                e.persist_stats(); // snapshot counters so a crash loses at most ~5 min
                e.expire_sweep();
                if let Err(err) = e.maybe_compact() {
                    tracing::warn!(%err, "compaction failed");
                }
            }
        });
    }

    // Nick protection: rename anyone who didn't identify to their registered nick
    // in time. Short cadence so the grace period is honoured closely.
    {
        let engine = engine.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                engine.lock().await.enforce_sweep();
            }
        });
    }

    // ChanFix scores op-time on a shorter cadence so the fix has fresh data.
    if enabled("chanfix") {
        let engine = engine.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(300)).await;
                engine.lock().await.chanfix_tick();
            }
        });
    }

    let addr = format!("{}:{}", cfg.uplink.host, cfg.uplink.port);
    tracing::info!(server = %cfg.server.name, %addr, "linking to uplink");
    // Run until the uplink loop ends or the process is asked to stop. Every
    // committed change is already fsync'd, so a clean stop loses nothing; this
    // just lets systemd stop us without waiting out the kill timeout.
    let shutdown_engine = engine.clone();
    tokio::select! {
        res = link::run(proto, engine, &addr, irc_rx, cfg.email.clone(), cfg.keycard.clone()) => res,
        _ = shutdown_signal() => {
            // Flush stat counters so a clean stop/restart keeps StatServ history.
            shutdown_engine.lock().await.persist_stats();
            tracing::info!("received shutdown signal, exiting");
            Ok(())
        }
    }
}

// Resolve on Ctrl-C or SIGTERM (systemd stop).
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = ctrl_c.await;
                return;
            }
        };
        tokio::select! {
            _ = ctrl_c => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
}
