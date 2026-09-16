use echo_api::{human_time, NetView, Priv, Sender, ServiceCtx, Store};
use echo_api::t;

// A cap so a broad glob can't flood the requesting oper.
const MAX_SHOWN: usize = 100;

// LIST <pattern>: list registered accounts matching a glob, with an admin overview
// per account (online/last-seen, channels founded, email state, suspension). Oper-only.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &dyn Store) {
    if !from.privs.has(Priv::Auspex) {
        ctx.notice(me, from.uid, "Access denied — LIST needs the \x02auspex\x02 privilege.");
        return;
    }
    let pattern = args.get(1).copied().unwrap_or("*");
    let mut matches = db.accounts_matching(pattern);
    matches.sort_by_key(|a| a.name.to_ascii_lowercase());

    ctx.notice(me, from.uid, t!(ctx, "Accounts matching \x02{pattern}\x02:", pattern = pattern));
    for a in matches.iter().take(MAX_SHOWN) {
        let seen = if !net.uids_logged_into(&a.name).is_empty() {
            "online".to_string()
        } else if a.last_seen == 0 {
            "never".to_string()
        } else {
            human_time(a.last_seen)
        };
        let email = match (&a.email, a.verified) {
            (Some(_), true) => "email \u{2713}",
            (Some(_), false) => "email unconfirmed",
            (None, _) => "no email",
        };
        let chans = db.channels_owned_by(&a.name).len();
        let susp = if db.suspension(&a.name).is_some() { "  \x02[SUSPENDED]\x02" } else { "" };
        ctx.notice(me, from.uid, t!(ctx,
            "  \x02{name}\x02 — reg {reg} \u{00b7} seen {seen} \u{00b7} {chans} chan(s) \u{00b7} {email}{susp}",
            name = a.name, reg = human_time(a.ts), seen = seen, chans = chans, email = email, susp = susp));
    }
    let more = if matches.len() > MAX_SHOWN { t!(ctx, ", showing the first {max}", max = MAX_SHOWN) } else { String::new() };
    ctx.notice(me, from.uid, echo_api::plural!(ctx, matches.len(), one = "End of list — {count} match{more}.", other = "End of list — {count} matches{more}.", count = matches.len(), more = more));
}
