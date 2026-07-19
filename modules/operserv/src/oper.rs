use echo_api::{parse_duration, Priv, Privs, Sender, ServiceCtx, Store};
use std::time::{SystemTime, UNIX_EPOCH};

// OPER ADD <account> <priv[,priv…]> [+duration] | OPER DEL <account> | OPER LIST:
// manage runtime services operators (merged with the declarative config opers).
// Privileges (low to high): auspex, oper, suspend, admin, root — or name a tier
// directly (operator/administrator/root), which grants the matching privilege.
// Root-only — granting operators is the top-tier power.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !from.privs.has(Priv::Root) {
        ctx.notice(me, from.uid, "Access denied — OPER needs the \x02root\x02 privilege.");
        return;
    }
    match args.get(1).map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("ADD") | Some("SET") => add(me, from, args.get(2).copied(), args.get(3).copied(), args.get(4).copied(), ctx, db),
        Some("DEL") | Some("REMOVE") => del(me, from, args.get(2).copied(), ctx, db),
        Some("LIST") | Some("VIEW") => list(me, from, ctx, db),
        _ => ctx.notice(me, from.uid, "Syntax: OPER ADD <account> <priv[,priv] | tier> [+duration] | OPER DEL <account> | OPER LIST — tiers: operator, administrator, root; privs: auspex, oper, suspend, admin, root"),
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
    // Parse the privilege names, rejecting the whole grant on a typo rather than
    // silently dropping it (which would grant less than the oper intended).
    let mut names = Vec::new();
    let mut unknown = Vec::new();
    for p in privs.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        match Priv::from_name(p) {
            Some(pr) => names.push(pr.name().to_string()),
            None => unknown.push(p.to_string()),
        }
    }
    if !unknown.is_empty() {
        ctx.notice(me, from.uid, format!("Unknown privilege(s): \x02{}\x02 (valid: {}).", unknown.join(", "), Priv::valid_names()));
        return;
    }
    if names.is_empty() {
        ctx.notice(me, from.uid, format!("No privileges given (valid: {}).", Priv::valid_names()));
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
        let tier = Privs::from_names(privs).tier();
        ctx.notice(me, from.uid, format!("  \x02{account}\x02 [{tier}] — {}{window}", privs.join(", ")));
    }
    ctx.notice(me, from.uid, format!("End of runtime operator list ({} shown).", opers.len()));
}
