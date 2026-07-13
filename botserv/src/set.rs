use fedserv_api::{parse_duration, ChanSetting, Sender, ServiceCtx, Store};

// SET <#channel> <option> <value>: per-channel bot options. Founder-or-admin.
// GREET <on|off> (show members' greets on join), BANEXPIRE <duration|off> (how
// long kicker bans last).
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let (Some(&chan), Some(option)) = (args.get(1), args.get(2)) else {
        ctx.notice(me, from.uid, "Syntax: SET <#channel> <GREET <ON|OFF> | BANEXPIRE <duration|off>>");
        return;
    };
    if !super::require_channel_admin(me, from, chan, ctx, db) {
        return;
    }

    // BANEXPIRE takes a duration, not ON/OFF.
    if option.eq_ignore_ascii_case("BANEXPIRE") {
        let Some(&arg) = args.get(3) else {
            ctx.notice(me, from.uid, "Syntax: SET <#channel> BANEXPIRE <duration|off> (e.g. 30m, 2h, off).");
            return;
        };
        let secs = if matches!(arg.to_ascii_lowercase().as_str(), "off" | "none" | "0") {
            0
        } else {
            match parse_duration(arg) {
                Some(s) => s.min(u32::MAX as u64) as u32,
                None => {
                    ctx.notice(me, from.uid, format!("\x02{arg}\x02 isn't a valid duration. Try 30m, 2h, 7d or \x02off\x02."));
                    return;
                }
            }
        };
        match db.set_ban_expire(chan, secs) {
            Ok(()) if secs == 0 => ctx.notice(me, from.uid, format!("Kicker bans in \x02{chan}\x02 won't expire automatically.")),
            Ok(()) => ctx.notice(me, from.uid, format!("Kicker bans in \x02{chan}\x02 will expire after \x02{arg}\x02.")),
            Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
        }
        return;
    }

    let on = match args.get(3).map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("ON") | Some("TRUE") => true,
        Some("OFF") | Some("FALSE") => false,
        _ => {
            ctx.notice(me, from.uid, "Syntax: SET <#channel> GREET <ON|OFF>");
            return;
        }
    };
    match option.to_ascii_uppercase().as_str() {
        "GREET" => match db.set_channel_setting(chan, ChanSetting::BotGreet, on) {
            Ok(()) if on => ctx.notice(me, from.uid, format!("Greet messages are now \x02on\x02 in \x02{chan}\x02.")),
            Ok(()) => ctx.notice(me, from.uid, format!("Greet messages are now \x02off\x02 in \x02{chan}\x02.")),
            Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
        },
        other => ctx.notice(me, from.uid, format!("Unknown option \x02{other}\x02. Available: \x02GREET\x02, \x02BANEXPIRE\x02.")),
    }
}
