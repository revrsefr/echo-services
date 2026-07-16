use echo_api::{Priv, Sender, ServiceCtx, Store};

// SET READONLY {ON|OFF}: put services into (or out of) read-only lockdown.
// While on, no new registrations or changes are accepted; existing data and
// gossip replication keep working. Admin-only. No argument reports the state.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — SET is for services operators.");
        return;
    }
    match args.get(1).map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("READONLY") => {
            let Some(on) = args.get(2).and_then(|s| parse_toggle(s)) else {
                let state = if db.readonly() { "ON" } else { "OFF" };
                ctx.notice(me, from.uid, format!("READONLY is currently \x02{state}\x02. Syntax: SET READONLY {{ON|OFF}}"));
                return;
            };
            db.set_readonly(on);
            if on {
                ctx.notice(me, from.uid, "Services are now \x02read-only\x02 — no changes will be accepted.");
            } else {
                ctx.notice(me, from.uid, "Services are no longer read-only.");
            }
        }
        _ => ctx.notice(me, from.uid, "Syntax: SET READONLY {ON|OFF}"),
    }
}

fn parse_toggle(s: &str) -> Option<bool> {
    match s.to_ascii_uppercase().as_str() {
        "ON" | "TRUE" | "YES" => Some(true),
        "OFF" | "FALSE" | "NO" => Some(false),
        _ => None,
    }
}
