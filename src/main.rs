// Core lives in src/; the pseudo-clients and the ircd link are external module
// crates (echo-nickserv, echo-chanserv, echo-inspircd), each depending
// only on the echo-api SDK.
mod config;
mod control;
mod dict;
mod engine;
mod gossip;
mod grpc;
mod health;
mod jsonrpc;
mod keycard;
mod link;
mod migrate;
mod proto;
mod version;
mod wiktionary;
#[cfg(test)]
mod i18n_check;

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
use echo_dictserv::DictServ;
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
    // `echorpc <cmd>` (a symlink to this binary) or `echo ctl <cmd>` runs the
    // control CLI against the daemon's gRPC Admin API instead of starting up.
    // Checked before `version` so `echorpc version` hits the live daemon, not the
    // static build banner.
    let arg0 = std::path::Path::new(argv.first().map(String::as_str).unwrap_or(""))
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("");
    if arg0 == "echorpc" || arg0 == "echoctl" {
        return control::run(argv[1..].to_vec()).await;
    }
    if argv.get(1).map(String::as_str) == Some("ctl") {
        return control::run(argv.get(2..).unwrap_or(&[]).to_vec()).await;
    }
    // `echo --version` / `-V` / `echo version` prints the build banner (version,
    // git revision, build date, toolchain, target) and exits.
    if matches!(argv.get(1).map(String::as_str), Some("--version") | Some("-V") | Some("version")) {
        use std::io::IsTerminal;
        println!("{}", version::banner(std::io::stdout().is_terminal()));
        return Ok(());
    }
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

    // `echo --gen-gossip-key` prints a fresh Ed25519 keypair for Tier C federation.
    if matches!(argv.get(1).map(String::as_str), Some("--gen-gossip-key") | Some("gen-gossip-key")) {
        let (secret, public) = engine::db::sign::generate();
        println!("# gossip signing keypair — keep `key` secret; publish `public` to your peers");
        println!("key    = \"{secret}\"");
        println!("public = \"{public}\"");
        return Ok(());
    }

    let path = std::env::args().nth(1).unwrap_or_else(|| "config.toml".to_string());
    // On an interactive run, greet with the full banner; under systemd (stderr is
    // journald, not a tty) skip it and let the structured log line below stand.
    if std::io::IsTerminal::is_terminal(&std::io::stderr()) {
        eprintln!("{}", version::banner(true));
    }
    tracing::info!(revision = %version::revision(), built = %version::built(), rustc = version::RUSTC, "starting {}", version::short());
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
    // DictServ is gated on its own [dictserv] config, not the module list — it's an
    // opt-in that makes outbound lookup requests, so it never loads by default.
    if cfg.dictserv.is_some() {
        services.push(Box::new(DictServ {
            uid: format!("{}AAAAAQ", cfg.server.sid),
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
    if let Some(sig) = cfg.gossip.as_ref().and_then(|g| g.signing.as_ref()) {
        match engine::db::sign::Signing::new(&sig.key, &sig.trust) {
            Ok(s) => {
                db.set_gossip_signing(s);
                tracing::info!(trusted = sig.trust.len(), "gossip signing enabled (Tier C per-origin signatures)");
            }
            Err(e) => {
                tracing::error!(%e, "invalid [gossip.signing] config");
                std::process::exit(1);
            }
        }
    }
    db.set_email_enabled(cfg.email.is_some());
    db.set_external_accounts(cfg.auth.as_ref().is_some_and(|a| a.external));
    db.set_confusable_check(cfg.register.confusable_check);
    if let Some(lang) = &cfg.language {
        db.set_default_language(&lang.default);
        db.set_available_languages(lang.available.clone());
        // Load a JSON catalog (english msgid -> translation) per non-English code.
        let mut catalog = std::collections::HashMap::new();
        for code in db.available_languages().to_vec() {
            if code == "en" {
                continue; // English needs no catalog: the msgid is the English text
            }
            let path = format!("{}/{}.json", lang.dir, code);
            match std::fs::read_to_string(&path) {
                Ok(data) => match serde_json::from_str::<std::collections::HashMap<String, String>>(&data) {
                    Ok(map) => {
                        tracing::info!(code = %code, entries = map.len(), "loaded translation catalog");
                        catalog.insert(code, map);
                    }
                    Err(e) => tracing::error!(%e, %path, "invalid translation catalog JSON"),
                },
                Err(e) => tracing::warn!(%e, %path, "translation catalog not found"),
            }
        }
        echo_api::load_catalog(catalog);
    }
    match cfg.extban.as_ref().map(|e| e.enabled.as_slice()) {
        Some(list) if !list.is_empty() => {
            db.set_extban_enabled(list.to_vec());
            tracing::info!(extbans = %list.join(" "), "extban policy: restricted to the configured set");
        }
        _ => tracing::info!("extban policy: all extbans the ircd offers are accepted"),
    }
    if let Some(log) = &cfg.log {
        if !log.notify_exclude.is_empty() {
            db.set_notify_exclude(log.notify_exclude.clone());
            tracing::info!(masks = %log.notify_exclude.join(" "), "notify: excluding masks from the staff feed");
        }
    }
    if let Some(email) = &cfg.email {
        db.set_email_brand(&email.brand);
        db.set_email_accent(&email.accent);
        db.set_email_logo(&email.logo);
    }
    let engine = Arc::new(Mutex::new(Engine::new(services, db)));

    // Channel for services-initiated actions to reach the uplink (drained by the link loop).
    let (irc_tx, irc_rx) = tokio::sync::mpsc::unbounded_channel();
    engine.lock().await.set_irc_out(irc_tx.clone());
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

    // Liveness + Prometheus metrics endpoint (plain HTTP, localhost).
    if let Some(health_cfg) = cfg.health.clone() {
        tokio::spawn(health::run(engine.clone(), health_cfg));
    }

    // Periodically fold log churn into a snapshot when it grows past the accounts.
    {
        let engine = engine.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(300)).await;
                let mut e = engine.lock().await;
                e.persist_stats(); // snapshot counters so a crash loses at most ~5 min
                e.persist_incidents(); // and the LOGSEARCH incident ring
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
        res = link::run(proto, engine, &addr, irc_rx, irc_tx, cfg.email.clone(), cfg.keycard.clone(), cfg.dictserv.as_ref().map(|d| d.server.clone())) => res,
        _ = shutdown_signal() => {
            // Flush stat counters + the incident ring so a clean stop/restart keeps
            // StatServ history and OperServ LOGSEARCH.
            {
                let mut e = shutdown_engine.lock().await;
                e.persist_stats();
                e.persist_incidents();
            }
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
