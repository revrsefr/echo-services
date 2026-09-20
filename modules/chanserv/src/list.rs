use echo_api::{glob_match, human_time, NetView, Priv, Sender, ServiceCtx, Store};
use echo_api::t;

// Cap so a broad LIST can't flood the requesting oper's send queue.
const MAX_SHOWN: usize = 100;

// LIST [pattern]: registered channels matching a glob. Non-opers get a public list
// (PRIVATE channels hidden); opers (auspex) get an admin overview per channel.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &dyn Store) {
    let pattern = args.get(1).copied().unwrap_or("*");
    let is_oper = from.privs.has(Priv::Auspex);
    let mut chans: Vec<_> = db
        .channels()
        .into_iter()
        .filter(|c| (is_oper || !c.private) && glob_match(pattern, &c.name))
        .collect();
    if chans.is_empty() {
        ctx.notice(me, from.uid, t!(ctx, "No channels match \x02{pattern}\x02.", pattern = pattern));
        return;
    }
    chans.sort_by_key(|c| c.name.to_ascii_lowercase());
    let total = chans.len();
    ctx.notice(me, from.uid, t!(ctx, "Channels matching \x02{pattern}\x02:", pattern = pattern));
    // Only the shown slice is enriched, so a broad glob never does N live lookups.
    for c in chans.iter().take(MAX_SHOWN) {
        let members = net.channel_members(&c.name).len();
        if is_oper {
            let mlock = {
                let on = if c.lock_on.is_empty() { String::new() } else { format!("+{}", c.lock_on) };
                let off = if c.lock_off.is_empty() { String::new() } else { format!("-{}", c.lock_off) };
                let m = format!("{on}{off}");
                if m.is_empty() { String::new() } else { format!(" \u{00b7} {m}") }
            };
            let susp = if db.channel_suspension(&c.name).is_some() { "  \x02[SUSPENDED]\x02" } else { "" };
            ctx.notice(me, from.uid, t!(ctx,
                "  \x02{name}\x02 — founder \x02{f}\x02 \u{00b7} {members} users \u{00b7} used {used}{mlock}{susp}",
                name = c.name, f = c.founder, members = members, used = human_time(c.last_used), mlock = mlock, susp = susp));
        } else {
            ctx.notice(me, from.uid, t!(ctx, "  \x02{name}\x02 ({members} users)", name = c.name, members = members));
        }
    }
    let more = if total > MAX_SHOWN { t!(ctx, ", showing the first {max}", max = MAX_SHOWN) } else { String::new() };
    ctx.notice(me, from.uid, echo_api::plural!(ctx, total, one = "End of list — {count} channel{more}.", other = "End of list — {count} channels{more}.", count = total, more = more));
}
