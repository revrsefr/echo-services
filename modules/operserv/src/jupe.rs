use echo_api::{t, Priv, Sender, ServiceCtx, Store};

// JUPE <server.name> [reason] | JUPE DEL <server.name> | JUPE LIST: hold a
// server name with a fake server so a rogue one can't link (or lift it). Admin-
// only. Node-local: the introducing node owns the jupe.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — JUPE needs the \x02admin\x02 privilege.");
        return;
    }
    match args.get(1) {
        Some(&sub) if sub.eq_ignore_ascii_case("DEL") || sub.eq_ignore_ascii_case("REMOVE") => del(me, from, args.get(2).copied(), ctx, db),
        Some(&sub) if sub.eq_ignore_ascii_case("LIST") => list(me, from, ctx, db),
        Some(&name) if name.contains('.') => {
            let reason = if args.len() > 2 { args[2..].join(" ") } else { "Juped by services".to_string() };
            let by = from.account.unwrap_or(from.nick);
            let sid = db.jupe_add(name, &format!("({by}) {reason}"));
            ctx.jupe(name, &sid, &format!("({by}) {reason}"));
            ctx.notice(me, from.uid, t!(ctx, "\x02{name}\x02 is now juped.", name = name));
        }
        _ => ctx.notice(me, from.uid, "Syntax: JUPE <server.name> [reason] | JUPE DEL <server.name> | JUPE LIST"),
    }
}

fn del(me: &str, from: &Sender, name: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(name) = name else {
        ctx.notice(me, from.uid, "Syntax: JUPE DEL <server.name>");
        return;
    };
    match db.jupe_del(name) {
        Some(sid) => {
            ctx.squit(&sid, "Jupe lifted");
            ctx.notice(me, from.uid, t!(ctx, "The jupe on \x02{name}\x02 has been lifted.", name = name));
        }
        None => ctx.notice(me, from.uid, t!(ctx, "\x02{name}\x02 isn't juped.", name = name)),
    }
}

fn list(me: &str, from: &Sender, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let jupes = db.jupes();
    if jupes.is_empty() {
        ctx.notice(me, from.uid, "No servers are juped.");
        return;
    }
    for (name, sid, reason) in &jupes {
        ctx.notice(me, from.uid, t!(ctx, "  \x02{name}\x02 ({sid}) — {reason}", name = name, sid = sid, reason = reason));
    }
    ctx.notice(me, from.uid, t!(ctx, "End of jupe list ({count} shown).", count = jupes.len()));
}
