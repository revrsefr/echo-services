use echo_api::{Sender, ServiceCtx, Store};

// FORBID <pattern>: block user-requested vhosts matching this regex (operators),
// e.g. (?i)(oper|admin|staff|services) to stop impersonation.
pub fn add(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !super::require_oper(me, from, ctx) {
        return;
    }
    if args.len() < 2 {
        ctx.notice(me, from.uid, "Syntax: FORBID <regex>");
        return;
    }
    let pattern = args[1..].join(" ");
    match db.vhost_forbid_add(&pattern) {
        Ok(true) => ctx.notice(me, from.uid, format!("Forbidden vhost pattern added: {pattern}")),
        Ok(false) => ctx.notice(me, from.uid, "That pattern is already forbidden."),
        Err(_) => ctx.notice(me, from.uid, format!("\x02{pattern}\x02 isn't a valid regular expression.")),
    }
}

// FORBIDLIST: the forbidden-pattern list (operators).
pub fn list(me: &str, from: &Sender, ctx: &mut ServiceCtx, db: &dyn Store) {
    if !super::require_oper(me, from, ctx) {
        return;
    }
    let forbidden = db.vhost_forbidden();
    if forbidden.is_empty() {
        ctx.notice(me, from.uid, "No vhost patterns are forbidden.");
        return;
    }
    ctx.notice(me, from.uid, format!("Forbidden vhost patterns ({}):", forbidden.len()));
    for (i, p) in forbidden.iter().enumerate() {
        ctx.notice(me, from.uid, format!("  {}. {p}", i + 1));
    }
}

// FORBIDDEL <number>: remove a forbidden pattern (operators).
pub fn del(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !super::require_oper(me, from, ctx) {
        return;
    }
    let Some(n) = args.get(1).and_then(|s| s.parse::<usize>().ok()) else {
        ctx.notice(me, from.uid, "Syntax: FORBIDDEL <number> (see FORBIDLIST)");
        return;
    };
    match db.vhost_forbid_del(n) {
        Ok(Some(pattern)) => ctx.notice(me, from.uid, format!("Removed forbidden pattern: {pattern}")),
        Ok(None) => ctx.notice(me, from.uid, format!("There's no forbidden pattern #\x02{n}\x02.")),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
