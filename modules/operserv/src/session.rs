use echo_api::{NetView, Priv, Sender, ServiceCtx, Store};

// SESSION LIST <min> | SESSION VIEW <ip>: inspect live per-IP session counts.
// EXCEPTION ADD <ip-mask> <limit> [reason] | DEL <ip-mask> | LIST: manage the
// per-IP-mask allowances that override the default limit. All admin-only.
pub fn handle_session(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView) {
    if !from.privs.has(Priv::Oper) {
        ctx.notice(me, from.uid, "Access denied — SESSION needs the \x02operator\x02 privilege.");
        return;
    }
    match args.get(1).map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("LIST") => {
            let min = args.get(2).and_then(|n| n.parse::<u32>().ok()).unwrap_or(2);
            let over = net.sessions_over(min);
            if over.is_empty() {
                ctx.notice(me, from.uid, format!("No IP has {min} or more sessions."));
                return;
            }
            for (ip, n) in &over {
                ctx.notice(me, from.uid, format!("  \x02{n}\x02 sessions from \x02{ip}\x02"));
            }
            ctx.notice(me, from.uid, format!("End of session list ({} IP(s)).", over.len()));
        }
        Some("VIEW") => {
            let Some(&ip) = args.get(2) else {
                ctx.notice(me, from.uid, "Syntax: SESSION VIEW <ip>");
                return;
            };
            ctx.notice(me, from.uid, format!("\x02{ip}\x02 has \x02{}\x02 live session(s).", net.session_count(ip)));
        }
        _ => ctx.notice(me, from.uid, "Syntax: SESSION LIST <min> | SESSION VIEW <ip>"),
    }
}

pub fn handle_exception(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — EXCEPTION needs the \x02admin\x02 privilege.");
        return;
    }
    match args.get(1).map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("ADD") => {
            let (Some(&mask), Some(limit)) = (args.get(2), args.get(3).and_then(|n| n.parse::<u32>().ok())) else {
                ctx.notice(me, from.uid, "Syntax: EXCEPTION ADD <ip-mask> <limit> [reason]");
                return;
            };
            let reason = if args.len() > 4 { args[4..].join(" ") } else { "No reason given".to_string() };
            db.session_except_add(mask, limit, &reason);
            let note = if limit == 0 { " (unlimited)".to_string() } else { format!(" (limit {limit})") };
            ctx.notice(me, from.uid, format!("Session exception for \x02{mask}\x02 set{note}."));
        }
        Some("DEL") | Some("REMOVE") => {
            let Some(&mask) = args.get(2) else {
                ctx.notice(me, from.uid, "Syntax: EXCEPTION DEL <ip-mask>");
                return;
            };
            if db.session_except_del(mask) {
                ctx.notice(me, from.uid, format!("Session exception for \x02{mask}\x02 removed."));
            } else {
                ctx.notice(me, from.uid, format!("No session exception matches \x02{mask}\x02."));
            }
        }
        Some("LIST") => {
            let list = db.session_exceptions();
            if list.is_empty() {
                ctx.notice(me, from.uid, "No session exceptions.");
                return;
            }
            for (mask, limit, reason) in &list {
                let lim = if *limit == 0 { "unlimited".to_string() } else { limit.to_string() };
                ctx.notice(me, from.uid, format!("  \x02{mask}\x02 → {lim} — {reason}"));
            }
            ctx.notice(me, from.uid, format!("End of exception list ({} shown).", list.len()));
        }
        _ => ctx.notice(me, from.uid, "Syntax: EXCEPTION ADD <ip-mask> <limit> [reason] | EXCEPTION DEL <ip-mask> | EXCEPTION LIST"),
    }
}
