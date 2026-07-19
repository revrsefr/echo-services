use echo_api::{human_time, Priv, Sender, ServiceCtx, Store};
use echo_api::t;

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

    ctx.notice(me, from.uid, t!(ctx, "Accounts matching \x02{pattern}\x02:", pattern = pattern));
    for a in matches.iter().take(MAX_SHOWN) {
        let flag = if a.verified { "" } else { " (unconfirmed)" };
        ctx.notice(me, from.uid, t!(ctx, "  \x02{name}\x02  registered {when}{flag}", name = a.name, when = human_time(a.ts), flag = flag));
    }
    let more = if matches.len() > MAX_SHOWN { t!(ctx, ", showing the first {max}", max = MAX_SHOWN) } else { String::new() };
    ctx.notice(me, from.uid, t!(ctx, "End of list — {count} match(es){more}.", count = matches.len(), more = more));
}
