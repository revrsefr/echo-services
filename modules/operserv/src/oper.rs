use echo_api::{parse_duration, Priv, Sender, ServiceCtx, Store};
use std::time::{SystemTime, UNIX_EPOCH};

// OPER ADD <account> <priv[,priv…]> [+duration] | OPER DEL <account> | OPER LIST:
// manage runtime services operators (merged with the declarative config opers).
// The privileges are auspex, suspend, admin; a +duration makes the grant expire.
// Admin-only — only an admin grants oper.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — OPER needs the \x02admin\x02 privilege.");
        return;
    }
    match args.get(1).map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("ADD") | Some("SET") => add(me, from, args.get(2).copied(), args.get(3).copied(), args.get(4).copied(), ctx, db),
        Some("DEL") | Some("REMOVE") => del(me, from, args.get(2).copied(), ctx, db),
        Some("LIST") | Some("VIEW") => list(me, from, ctx, db),
        _ => ctx.notice(me, from.uid, "Syntax: OPER ADD <account> <priv[,priv]> [+duration] | OPER DEL <account> | OPER LIST — privs: auspex, suspend, admin"),
    }
}

fn add(me: &str, from: &Sender, account: Option<&str>, privs: Option<&str>, dur: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let (Some(account), Some(privs)) = (account, privs) else {
        ctx.notice(me, from.uid, "Syntax: OPER ADD <account> <priv[,priv]> [+duration]");
        return;
    };
    let Some(account) = db.resolve_account(account).map(str::to_string) else {
        ctx.notice(me, from.uid, format!("\x02{account}\x02 isn't registered."));
        return;
    };
    // Keep only recognised privilege names.
    let names: Vec<String> = privs
        .split(',')
        .map(|p| p.trim().to_ascii_lowercase())
        .filter(|p| matches!(p.as_str(), "auspex" | "suspend" | "admin"))
        .collect();
    if names.is_empty() {
        ctx.notice(me, from.uid, "No valid privileges given (auspex, suspend, admin).");
        return;
    }
    let expires = dur.and_then(|d| d.strip_prefix('+')).and_then(parse_duration).map(|secs| now() + secs);
    db.oper_grant(&account, names.clone(), expires);
    let window = if expires.is_some() { " (temporary)" } else { "" };
    ctx.notice(me, from.uid, format!("\x02{account}\x02 is now an operator ({}){window}.", names.join(", ")));
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn del(me: &str, from: &Sender, account: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(account) = account else {
        ctx.notice(me, from.uid, "Syntax: OPER DEL <account>");
        return;
    };
    let canonical = db.resolve_account(account).map(str::to_string).unwrap_or_else(|| account.to_string());
    if db.oper_revoke(&canonical) {
        ctx.notice(me, from.uid, format!("\x02{canonical}\x02 is no longer a runtime operator."));
    } else {
        ctx.notice(me, from.uid, format!("\x02{account}\x02 isn't a runtime operator (config opers are set in the daemon config)."));
    }
}

fn list(me: &str, from: &Sender, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let opers = db.opers_list();
    if opers.is_empty() {
        ctx.notice(me, from.uid, "No runtime operators (config opers are set in the daemon config).");
        return;
    }
    for (account, privs, expires) in &opers {
        let window = if expires.is_some() { " (temporary)" } else { "" };
        ctx.notice(me, from.uid, format!("  \x02{account}\x02 — {}{window}", privs.join(", ")));
    }
    ctx.notice(me, from.uid, format!("End of runtime operator list ({} shown).", opers.len()));
}
