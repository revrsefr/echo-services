use echo_api::{human_time, Priv, Sender, ServiceCtx, Store};

// A cap so a broad glob can't flood the requesting oper.
const MAX_SHOWN: usize = 100;

// LIST <pattern>: list registered accounts matching a glob. Oper-only.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &dyn Store) {
    if !from.privs.has(Priv::Auspex) {
        ctx.notice(me, from.uid, "Access denied — LIST needs the \x02auspex\x02 privilege.");
        return;
    }
    let pattern = args.get(1).copied().unwrap_or("*");
    let mut matches = db.accounts_matching(pattern);
    matches.sort_by_key(|a| a.name.to_ascii_lowercase());

    ctx.notice(me, from.uid, format!("Accounts matching \x02{pattern}\x02:"));
    for a in matches.iter().take(MAX_SHOWN) {
        let flag = if a.verified { "" } else { " (unconfirmed)" };
        ctx.notice(me, from.uid, format!("  \x02{}\x02  registered {}{}", a.name, human_time(a.ts), flag));
    }
    let more = if matches.len() > MAX_SHOWN { format!(", showing the first {MAX_SHOWN}") } else { String::new() };
    ctx.notice(me, from.uid, format!("End of list — {} match(es){more}.", matches.len()));
}
