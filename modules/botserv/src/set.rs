use echo_api::{parse_duration, t, ChanSetting, Priv, Sender, ServiceCtx, Store};

// SET <#channel> <option> <value>: per-channel bot options (founder-or-admin) —
// GREET <on|off>, BANEXPIRE <duration|off>, NOBOT <on|off>. Also
// SET <bot> PRIVATE <on|off> (services-admin only).
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let (Some(&target), Some(option)) = (args.get(1), args.get(2)) else {
        ctx.notice(me, from.uid, "Syntax: SET <#channel> <GREET|BANEXPIRE|NOBOT> <value>, or SET <bot> PRIVATE <ON|OFF>");
        return;
    };

    // A non-channel target names a bot: the only per-bot option is PRIVATE, and
    // it is services-admin only.
    if !target.starts_with('#') {
        if !from.privs.has(Priv::Admin) {
            ctx.notice(me, from.uid, "Access denied — managing bots is for services operators.");
            return;
        }
        let on = match (option.eq_ignore_ascii_case("PRIVATE"), args.get(3).map(|s| s.to_ascii_uppercase()).as_deref()) {
            (true, Some("ON")) => true,
            (true, Some("OFF")) => false,
            (true, _) => {
                ctx.notice(me, from.uid, "Syntax: SET <bot> PRIVATE <ON|OFF>");
                return;
            }
            (false, _) => {
                ctx.notice(me, from.uid, t!(ctx, "Unknown bot option \x02{option}\x02. Available: \x02PRIVATE\x02.", option = option));
                return;
            }
        };
        match db.bot_set_private(target, on) {
            Ok(true) if on => ctx.notice(me, from.uid, t!(ctx, "Bot \x02{nick}\x02 is now private (operators only).", nick = target)),
            Ok(true) => ctx.notice(me, from.uid, t!(ctx, "Bot \x02{nick}\x02 is now public.", nick = target)),
            Ok(false) => ctx.notice(me, from.uid, t!(ctx, "There's no bot named \x02{nick}\x02.", nick = target)),
            Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
        }
        return;
    }

    let chan = target;
    if !super::require_channel_admin(me, from, chan, ctx, db) {
        return;
    }

    // VOTEKICK takes a vote count (0 = off), not ON/OFF.
    if option.eq_ignore_ascii_case("VOTEKICK") {
        match args.get(3).and_then(|s| s.parse::<u16>().ok()) {
            Some(n) => match db.set_votekick(chan, n) {
                Ok(()) if n == 0 => ctx.notice(me, from.uid, t!(ctx, "\x02!votekick\x02 is now disabled in \x02{chan}\x02.", chan = chan)),
                Ok(()) => ctx.notice(me, from.uid, echo_api::plural!(ctx, n, one = "\x02{n}\x02 vote will now carry a \x02!votekick\x02/\x02!voteban\x02 in \x02{chan}\x02.", other = "\x02{n}\x02 votes will now carry a \x02!votekick\x02/\x02!voteban\x02 in \x02{chan}\x02.", n = n, chan = chan)),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            },
            None => ctx.notice(me, from.uid, "Syntax: SET <#channel> VOTEKICK <number> (0 to disable)"),
        }
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
                    ctx.notice(me, from.uid, t!(ctx, "\x02{arg}\x02 isn't a valid duration. Try 30m, 2h, 7d or \x02off\x02.", arg = arg));
                    return;
                }
            }
        };
        match db.set_ban_expire(chan, secs) {
            Ok(()) if secs == 0 => ctx.notice(me, from.uid, t!(ctx, "Kicker bans in \x02{chan}\x02 won't expire automatically.", chan = chan)),
            Ok(()) => ctx.notice(me, from.uid, t!(ctx, "Kicker bans in \x02{chan}\x02 will expire after \x02{arg}\x02.", chan = chan, arg = arg)),
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
            Ok(()) if on => ctx.notice(me, from.uid, t!(ctx, "Greet messages are now \x02on\x02 in \x02{chan}\x02.", chan = chan)),
            Ok(()) => ctx.notice(me, from.uid, t!(ctx, "Greet messages are now \x02off\x02 in \x02{chan}\x02.", chan = chan)),
            Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
        },
        "NOBOT" => match db.set_channel_setting(chan, ChanSetting::NoBot, on) {
            Ok(()) if on => ctx.notice(me, from.uid, t!(ctx, "Only operators may (un)assign a bot in \x02{chan}\x02 now.", chan = chan)),
            Ok(()) => ctx.notice(me, from.uid, t!(ctx, "The founder may (un)assign a bot in \x02{chan}\x02 again.", chan = chan)),
            Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
        },
        other => ctx.notice(me, from.uid, t!(ctx, "Unknown option \x02{other}\x02. Available: \x02GREET\x02, \x02BANEXPIRE\x02, \x02NOBOT\x02.", other = other)),
    }
}
