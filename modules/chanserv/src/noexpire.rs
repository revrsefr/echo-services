use echo_api::{Priv, Sender, ServiceCtx, Store};

// NOEXPIRE <#channel> {ON|OFF}: pin a channel so inactivity-expiry never drops
// it (or lift the pin). Oper-only (Priv::Admin).
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — that command is for services operators.");
        return;
    }
    let (Some(&chan), Some(on)) = (args.get(1), args.get(2).and_then(|s| parse_toggle(s))) else {
        ctx.notice(me, from.uid, "Syntax: NOEXPIRE <#channel> {ON|OFF}");
        return;
    };
    if db.channel(chan).is_none() {
        ctx.notice(me, from.uid, format!("\x02{chan}\x02 isn't registered."));
        return;
    }
    match db.set_channel_noexpire(chan, on) {
        Ok(true) if on => ctx.notice(me, from.uid, format!("\x02{chan}\x02 will no longer expire.")),
        Ok(true) => ctx.notice(me, from.uid, format!("\x02{chan}\x02 can expire from inactivity again.")),
        Ok(false) => ctx.notice(me, from.uid, format!("\x02{chan}\x02 was already set that way.")),
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
