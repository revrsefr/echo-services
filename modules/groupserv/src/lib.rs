//! GroupServ manages user groups — a `!name` owning a set of member accounts.
//! A group's real purpose is the interconnection: a channel can grant access to
//! a `!group` (via ChanServ FLAGS/ACCESS), and every member then inherits that
//! channel access. Members carry group-access flags (the same flag primitive
//! ChanServ uses): F founder, f manage members, i invite, c channel-access,
//! s set, m memo. Managing members needs the founder or the `f` flag.

use fedserv_api::{apply_flags, NetView, Sender, Service, ServiceCtx, Store, GROUP_FLAGS};

pub struct GroupServ {
    pub uid: String,
}

impl Service for GroupServ {
    fn nick(&self) -> &str {
        "GroupServ"
    }
    fn uid(&self) -> &str {
        &self.uid
    }
    fn gecos(&self) -> &str {
        "Group Service"
    }

    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, _net: &dyn NetView, db: &mut dyn Store) {
        let me = self.uid.as_str();
        match args.first().map(|s| s.to_ascii_uppercase()).as_deref() {
            Some("REGISTER") => register(me, from, args.get(1).copied(), ctx, db),
            Some("DROP") => drop(me, from, args.get(1).copied(), ctx, db),
            Some("INFO") => info(me, from, args.get(1).copied(), ctx, db),
            Some("LIST") => list(me, from, ctx, db),
            Some("ADD") => add(me, from, args.get(1).copied(), args.get(2).copied(), ctx, db),
            Some("DEL") => del(me, from, args.get(1).copied(), args.get(2).copied(), ctx, db),
            Some("FLAGS") => flags(me, from, args.get(1).copied(), args.get(2).copied(), args.get(3).copied(), ctx, db),
            Some("HELP") | None => help(me, from, ctx),
            Some(other) => ctx.notice(me, from.uid, format!("I don't know \x02{other}\x02. Try \x02HELP\x02.")),
        }
    }
}

fn help(me: &str, from: &Sender, ctx: &mut ServiceCtx) {
    ctx.notice(me, from.uid, "GroupServ manages user groups. \x02REGISTER\x02 <!group>, \x02DROP\x02 <!group>, \x02INFO\x02 <!group>, \x02LIST\x02, \x02ADD\x02/\x02DEL\x02 <!group> <account>, \x02FLAGS\x02 <!group> [account [+/-flags]]. Grant a group channel access with ChanServ \x02FLAGS #chan !group +o\x02 — every member then inherits it.");
}

// The caller must be logged in; returns their account.
fn account<'a>(me: &str, from: &'a Sender, ctx: &mut ServiceCtx) -> Option<&'a str> {
    match from.account {
        Some(a) => Some(a),
        None => {
            ctx.notice(me, from.uid, "You need to be logged in. Identify to NickServ first.");
            None
        }
    }
}

// Whether `who` may manage `group` (founder, or holds the F/f flag).
fn can_manage(group: &fedserv_api::GroupView, who: &str) -> bool {
    group.founder.eq_ignore_ascii_case(who)
        || group.members.iter().any(|m| m.account.eq_ignore_ascii_case(who) && (m.flags.contains('F') || m.flags.contains('f')))
}

fn register(me: &str, from: &Sender, name: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(acc) = account(me, from, ctx) else { return };
    let Some(name) = name else {
        ctx.notice(me, from.uid, "Syntax: REGISTER <!group>");
        return;
    };
    if !name.starts_with('!') || name.len() < 2 {
        ctx.notice(me, from.uid, "A group name starts with \x02!\x02, e.g. \x02!staff\x02.");
        return;
    }
    let acc = acc.to_string();
    match db.group_register(name, &acc) {
        Ok(()) => ctx.notice(me, from.uid, format!("Group \x02{name}\x02 registered — you're the founder.")),
        Err(fedserv_api::ChanError::Exists) => ctx.notice(me, from.uid, format!("\x02{name}\x02 is already registered.")),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}

fn drop(me: &str, from: &Sender, name: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(acc) = account(me, from, ctx) else { return };
    let Some(name) = name else {
        ctx.notice(me, from.uid, "Syntax: DROP <!group>");
        return;
    };
    let Some(g) = db.group(name) else {
        ctx.notice(me, from.uid, format!("\x02{name}\x02 isn't registered."));
        return;
    };
    if !g.founder.eq_ignore_ascii_case(acc) {
        ctx.notice(me, from.uid, format!("Only \x02{name}\x02's founder can drop it."));
        return;
    }
    match db.group_drop(name) {
        Ok(()) => ctx.notice(me, from.uid, format!("Group \x02{name}\x02 has been dropped.")),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}

fn info(me: &str, from: &Sender, name: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(name) = name else {
        ctx.notice(me, from.uid, "Syntax: INFO <!group>");
        return;
    };
    let Some(g) = db.group(name) else {
        ctx.notice(me, from.uid, format!("\x02{name}\x02 isn't registered."));
        return;
    };
    ctx.notice(me, from.uid, format!("Information for \x02{}\x02:", g.name));
    ctx.notice(me, from.uid, format!("  Founder : \x02{}\x02", g.founder));
    ctx.notice(me, from.uid, format!("  Members : {}", g.members.len()));
}

fn list(me: &str, from: &Sender, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    // Operators see every group; others see the ones they belong to.
    let names = if from.privs.any() {
        db.groups()
    } else if let Some(acc) = from.account {
        db.groups_of(acc)
    } else {
        Vec::new()
    };
    if names.is_empty() {
        ctx.notice(me, from.uid, "No groups to show.");
        return;
    }
    for n in &names {
        ctx.notice(me, from.uid, format!("  \x02{n}\x02"));
    }
    ctx.notice(me, from.uid, format!("End of list ({} group(s)).", names.len()));
}

fn add(me: &str, from: &Sender, name: Option<&str>, target: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(acc) = account(me, from, ctx) else { return };
    let (Some(name), Some(target)) = (name, target) else {
        ctx.notice(me, from.uid, "Syntax: ADD <!group> <account>");
        return;
    };
    let Some(g) = db.group(name) else {
        ctx.notice(me, from.uid, format!("\x02{name}\x02 isn't registered."));
        return;
    };
    if !can_manage(&g, acc) {
        ctx.notice(me, from.uid, format!("You need the founder or the \x02f\x02 flag to manage \x02{name}\x02."));
        return;
    }
    let Some(canonical) = db.resolve_account(target).map(str::to_string) else {
        ctx.notice(me, from.uid, format!("\x02{target}\x02 isn't registered."));
        return;
    };
    match db.group_set_flags(name, &canonical, "") {
        Ok(()) => ctx.notice(me, from.uid, format!("Added \x02{canonical}\x02 to \x02{name}\x02.")),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}

fn del(me: &str, from: &Sender, name: Option<&str>, target: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(acc) = account(me, from, ctx) else { return };
    let (Some(name), Some(target)) = (name, target) else {
        ctx.notice(me, from.uid, "Syntax: DEL <!group> <account>");
        return;
    };
    let Some(g) = db.group(name) else {
        ctx.notice(me, from.uid, format!("\x02{name}\x02 isn't registered."));
        return;
    };
    if !can_manage(&g, acc) {
        ctx.notice(me, from.uid, format!("You need the founder or the \x02f\x02 flag to manage \x02{name}\x02."));
        return;
    }
    match db.group_del_member(name, target) {
        Ok(true) => ctx.notice(me, from.uid, format!("Removed \x02{target}\x02 from \x02{name}\x02.")),
        Ok(false) => ctx.notice(me, from.uid, format!("\x02{target}\x02 isn't in \x02{name}\x02.")),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}

fn flags(me: &str, from: &Sender, name: Option<&str>, target: Option<&str>, delta: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(acc) = account(me, from, ctx) else { return };
    let Some(name) = name else {
        ctx.notice(me, from.uid, "Syntax: FLAGS <!group> [account [+/-flags]]");
        return;
    };
    let Some(g) = db.group(name) else {
        ctx.notice(me, from.uid, format!("\x02{name}\x02 isn't registered."));
        return;
    };
    // List.
    let Some(target) = target else {
        ctx.notice(me, from.uid, format!("Flags for \x02{}\x02:", g.name));
        ctx.notice(me, from.uid, format!("  \x02{}\x02 (founder): \x02F\x02", g.founder));
        for m in &g.members {
            ctx.notice(me, from.uid, format!("  \x02{}\x02: \x02{}\x02", m.account, if m.flags.is_empty() { "(member)" } else { &m.flags }));
        }
        return;
    };
    let current = g.members.iter().find(|m| m.account.eq_ignore_ascii_case(target)).map(|m| m.flags.clone());
    // Show one.
    let Some(delta) = delta else {
        match current {
            Some(f) => ctx.notice(me, from.uid, format!("\x02{target}\x02 in \x02{name}\x02: \x02{}\x02", if f.is_empty() { "(member)" } else { &f })),
            None => ctx.notice(me, from.uid, format!("\x02{target}\x02 isn't in \x02{name}\x02.")),
        }
        return;
    };
    // Change — needs founder or f flag.
    if !can_manage(&g, acc) {
        ctx.notice(me, from.uid, format!("You need the founder or the \x02f\x02 flag to change \x02{name}\x02."));
        return;
    }
    let Some(canonical) = db.resolve_account(target).map(str::to_string) else {
        ctx.notice(me, from.uid, format!("\x02{target}\x02 isn't registered."));
        return;
    };
    let updated = match apply_flags(current.as_deref().unwrap_or(""), delta, GROUP_FLAGS) {
        Ok(f) => f,
        Err(bad) => {
            ctx.notice(me, from.uid, format!("\x02{bad}\x02 isn't a valid group flag. Valid: \x02{GROUP_FLAGS}\x02."));
            return;
        }
    };
    match db.group_set_flags(name, &canonical, &updated) {
        Ok(()) => ctx.notice(me, from.uid, format!("\x02{canonical}\x02 in \x02{name}\x02 now holds \x02{}\x02.", if updated.is_empty() { "(member)" } else { &updated })),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
