use echo_api::{Priv, Sender, ServiceCtx, Store};

// PROTECT ALL | <account> [ON|OFF]: turn NickServ nick-protection (the
// identify-or-be-renamed enforcement) on or off for accounts. ALL enables it on
// every account that currently has it off — useful after a migration that
// carried protection over as off. Admin-only.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — PROTECT needs the \x02admin\x02 privilege.");
        return;
    }
    match args.get(1) {
        Some(t) if t.eq_ignore_ascii_case("ALL") => {
            let mut n = 0;
            for a in db.accounts_matching("*") {
                if !db.account_wants_protect(&a.name) && db.set_account_kill(&a.name, true).is_ok() {
                    n += 1;
                }
            }
            ctx.notice(me, from.uid, format!("Enabled nick protection on \x02{n}\x02 account(s) that had it off."));
            ctx.alert("OPER", format!("enabled nick protection on {n} accounts (PROTECT ALL)"));
        }
        Some(&account) => {
            if !db.exists(account) {
                ctx.notice(me, from.uid, format!("\x02{account}\x02 isn't registered."));
                return;
            }
            let on = !matches!(args.get(2).map(|s| s.to_ascii_uppercase()).as_deref(), Some("OFF"));
            if db.set_account_kill(account, on).is_ok() {
                ctx.notice(me, from.uid, format!("Nick protection for \x02{account}\x02 is now \x02{}\x02.", if on { "on" } else { "off" }));
            } else {
                ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment.");
            }
        }
        None => ctx.notice(me, from.uid, "Syntax: PROTECT ALL | <account> [ON|OFF]"),
    }
}
