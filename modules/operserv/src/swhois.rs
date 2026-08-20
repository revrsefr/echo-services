use echo_api::{t, NetView, Priv, Sender, ServiceCtx, Store};

// SWHOIS <account> [text...]: set an extra WHOIS line on an account (e.g.
// "is a Network Administrator"). It's stored on the account and re-applied to the
// ircd every time they log in, so it survives reconnects. With no text it shows the
// current line; a bare "-" clears it. Reading needs operator; changing needs admin.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &mut dyn Store) {
    let Some(target) = args.get(1).copied() else {
        ctx.notice(me, from.uid, "Syntax: SWHOIS <account> [text] — no text shows the line, a bare \x02-\x02 clears it.");
        return;
    };
    let Some(account) = db.resolve_account(target).map(str::to_string) else {
        ctx.notice(me, from.uid, t!(ctx, "There's no {kind} \x02{target}\x02.", kind = "account", target = target));
        return;
    };
    let rest = args.get(2..).unwrap_or(&[]).join(" ");
    // No argument: just show what's currently set (operator is enough).
    if rest.trim().is_empty() {
        match db.swhois(&account) {
            Some(line) => ctx.notice(me, from.uid, format!("SWHOIS on \x02{account}\x02: {line}")),
            None => ctx.notice(me, from.uid, format!("\x02{account}\x02 has no SWHOIS line.")),
        }
        return;
    }
    // Changing it sets a public WHOIS title, so require the admin privilege.
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — changing a SWHOIS needs the \x02admin\x02 privilege.");
        return;
    }
    let value = if rest.trim() == "-" { None } else { Some(rest) };
    if db.set_swhois(&account, value.clone()).is_err() {
        ctx.notice(me, from.uid, format!("Couldn't update \x02{account}\x02."));
        return;
    }
    // Apply it live to every session currently logged into the account (an empty
    // value clears the line on the ircd).
    let wire = value.clone().unwrap_or_default();
    for uid in net.uids_logged_into(&account) {
        ctx.metadata(&uid, "swhois", &wire);
    }
    match &value {
        Some(line) => ctx.notice(me, from.uid, format!("SWHOIS on \x02{account}\x02 set to: {line}")),
        None => ctx.notice(me, from.uid, format!("SWHOIS on \x02{account}\x02 cleared.")),
    }
}
