use fedserv_api::{apply_flags, Sender, ServiceCtx, Store, ACCESS_FLAGS};

// FLAGS <#channel> [account [+/-flags]]: the granular access model. With no
// account, list the access entries and their flags; with an account, show or
// change its flags. Letters: f full o auto-op O op h auto-halfop v auto-voice
// t topic i invite a access-list s settings g greet. Viewing needs op access;
// changing needs the founder or the \x02a\x02 flag.
pub fn handle(me: &str, from: &Sender, chan: &str, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(info) = db.channel(chan) else {
        ctx.notice(me, from.uid, format!("\x02{chan}\x02 isn't registered."));
        return;
    };
    let is_founder = from.account == Some(info.founder.as_str());
    let caps = info.caps_of(from.account);

    // FLAGS <#chan> — list.
    let Some(&target) = args.get(2) else {
        if !is_founder && !caps.op {
            ctx.notice(me, from.uid, format!("You need access to \x02{chan}\x02 to view its flags."));
            return;
        }
        ctx.notice(me, from.uid, format!("Access flags for \x02{chan}\x02:"));
        ctx.notice(me, from.uid, format!("  \x02{}\x02 (founder): \x02f\x02", info.founder));
        for a in &info.access {
            ctx.notice(me, from.uid, format!("  \x02{}\x02: \x02{}\x02", a.account, display_flags(&a.level)));
        }
        ctx.notice(me, from.uid, format!("End of flags ({} entr{}).", info.access.len() + 1, if info.access.is_empty() { "y" } else { "ies" }));
        return;
    };

    let current = info.access.iter().find(|a| a.account.eq_ignore_ascii_case(target)).map(|a| display_flags(&a.level));

    // FLAGS <#chan> <account> — show one.
    let Some(&delta) = args.get(3) else {
        match current {
            Some(f) if !f.is_empty() => ctx.notice(me, from.uid, format!("\x02{target}\x02 on \x02{chan}\x02: \x02{f}\x02")),
            _ => ctx.notice(me, from.uid, format!("\x02{target}\x02 has no access to \x02{chan}\x02.")),
        }
        return;
    };

    // FLAGS <#chan> <account> <+/-flags> — modify.
    if !is_founder && !caps.access {
        ctx.notice(me, from.uid, format!("You need the founder or the \x02a\x02 flag to change access on \x02{chan}\x02."));
        return;
    }
    if info.founder.eq_ignore_ascii_case(target) {
        ctx.notice(me, from.uid, "The founder's access is set with \x02SET FOUNDER\x02, not flags.");
        return;
    }
    let base = current.unwrap_or_default();
    let updated = match apply_flags(&base, delta, ACCESS_FLAGS) {
        Ok(f) => f,
        Err(bad) => {
            ctx.notice(me, from.uid, format!("\x02{bad}\x02 isn't a valid flag. Valid flags: \x02{ACCESS_FLAGS}\x02."));
            return;
        }
    };
    if updated.is_empty() {
        match db.access_del(chan, target) {
            Ok(true) => ctx.notice(me, from.uid, format!("Cleared \x02{target}\x02's access to \x02{chan}\x02.")),
            _ => ctx.notice(me, from.uid, format!("\x02{target}\x02 had no access to \x02{chan}\x02.")),
        }
        return;
    }
    match db.access_add(chan, target, &updated) {
        Ok(()) => ctx.notice(me, from.uid, format!("\x02{target}\x02 on \x02{chan}\x02 now holds \x02{updated}\x02.")),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}

// Show a stored level as flag letters (mapping the legacy presets).
fn display_flags(level: &str) -> String {
    match level {
        "op" => "oti".to_string(),
        "voice" => "v".to_string(),
        "founder" => "f".to_string(),
        flags => flags.to_string(),
    }
}
