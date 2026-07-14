use echo_api::{Priv, Sender, ServiceCtx, Store};

// NOEXPIRE <account> {ON|OFF}: pin an account so inactivity-expiry never drops
// it (or lift the pin). Oper-only (Priv::Admin) — protecting a record from
// expiry is a staff decision, not self-service.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — that command is for services operators.");
        return;
    }
    let (Some(&target), Some(on)) = (args.get(1), args.get(2).and_then(|s| parse_toggle(s))) else {
        ctx.notice(me, from.uid, "Syntax: NOEXPIRE <account> {ON|OFF}");
        return;
    };
    let Some(account) = db.resolve_account(target).map(str::to_string) else {
        ctx.notice(me, from.uid, format!("\x02{target}\x02 isn't registered."));
        return;
    };
    match db.set_account_noexpire(&account, on) {
        Ok(true) if on => ctx.notice(me, from.uid, format!("\x02{account}\x02 will no longer expire.")),
        Ok(true) => ctx.notice(me, from.uid, format!("\x02{account}\x02 can expire from inactivity again.")),
        Ok(false) => ctx.notice(me, from.uid, format!("\x02{account}\x02 was already set that way.")),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}

fn parse_toggle(s: &str) -> Option<bool> {
    match s.to_ascii_uppercase().as_str() {
        "ON" | "TRUE" | "YES" => Some(true),
        "OFF" | "FALSE" | "NO" => Some(false),
        _ => None,
    }
}
