use fedserv_api::{Kicker, Sender, ServiceCtx, Store};

// KICK <#channel> <type> {ON|OFF} [params]: configure the bot's kickers.
// Types: CAPS [min [percent]], BOLDS, COLORS, UNDERLINES, REVERSES, ITALICS,
// and the exemption DONTKICKOPS. Founder-or-admin.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let (Some(&chan), Some(kind)) = (args.get(1), args.get(2)) else {
        ctx.notice(me, from.uid, "Syntax: KICK <#channel> <CAPS|FLOOD|REPEAT|BOLDS|COLORS|UNDERLINES|REVERSES|ITALICS|DONTKICKOPS> <ON|OFF> [params]");
        return;
    };
    if !super::require_channel_admin(me, from, chan, ctx, db) {
        return;
    }
    let on = match args.get(3).map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("ON") | Some("TRUE") => true,
        Some("OFF") | Some("FALSE") => false,
        _ => {
            ctx.notice(me, from.uid, "Say \x02ON\x02 or \x02OFF\x02, e.g. KICK #channel CAPS ON.");
            return;
        }
    };

    // CAPS/FLOOD/REPEAT carry optional thresholds when turned on.
    if kind.eq_ignore_ascii_case("CAPS") {
        if on {
            let min = args.get(4).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
            let percent = args.get(5).and_then(|s| s.parse::<u16>().ok()).filter(|p| (1..=100).contains(p)).unwrap_or(0);
            match db.set_caps_kicker(chan, min, percent) {
                Ok(()) => ctx.notice(me, from.uid, format!("The bot will now kick for \x02caps\x02 in \x02{chan}\x02.")),
                Err(_) => reg_error(me, from, chan, ctx),
            }
        } else {
            toggle(me, from, chan, Kicker::Caps, false, ctx, db);
        }
        return;
    }
    if kind.eq_ignore_ascii_case("FLOOD") {
        if on {
            let lines = args.get(4).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
            let secs = args.get(5).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
            match db.set_flood_kicker(chan, lines, secs) {
                Ok(()) => ctx.notice(me, from.uid, format!("The bot will now kick for \x02flooding\x02 in \x02{chan}\x02.")),
                Err(_) => reg_error(me, from, chan, ctx),
            }
        } else {
            toggle(me, from, chan, Kicker::Flood, false, ctx, db);
        }
        return;
    }
    if kind.eq_ignore_ascii_case("REPEAT") {
        if on {
            let times = args.get(4).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
            match db.set_repeat_kicker(chan, times) {
                Ok(()) => ctx.notice(me, from.uid, format!("The bot will now kick for \x02repeating\x02 in \x02{chan}\x02.")),
                Err(_) => reg_error(me, from, chan, ctx),
            }
        } else {
            toggle(me, from, chan, Kicker::Repeat, false, ctx, db);
        }
        return;
    }

    let kicker = match kind.to_ascii_uppercase().as_str() {
        "BOLDS" => Kicker::Bolds,
        "COLORS" | "COLOURS" => Kicker::Colors,
        "UNDERLINES" => Kicker::Underlines,
        "REVERSES" => Kicker::Reverses,
        "ITALICS" => Kicker::Italics,
        "BADWORDS" => Kicker::Badwords,
        "DONTKICKOPS" => Kicker::DontKickOps,
        other => {
            ctx.notice(me, from.uid, format!("Unknown kicker \x02{other}\x02. Try CAPS, FLOOD, REPEAT, BOLDS, COLORS, UNDERLINES, REVERSES, ITALICS or DONTKICKOPS."));
            return;
        }
    };
    toggle(me, from, chan, kicker, on, ctx, db);
}

fn label(kicker: Kicker) -> &'static str {
    match kicker {
        Kicker::Caps => "caps",
        Kicker::Bolds => "bolds",
        Kicker::Colors => "colours",
        Kicker::Underlines => "underlines",
        Kicker::Reverses => "reverses",
        Kicker::Italics => "italics",
        Kicker::Flood => "flood",
        Kicker::Repeat => "repeat",
        Kicker::Badwords => "badwords",
        Kicker::DontKickOps => "dontkickops",
    }
}

fn toggle(me: &str, from: &Sender, chan: &str, kicker: Kicker, on: bool, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    match db.set_kicker(chan, kicker, on) {
        Ok(()) if kicker == Kicker::DontKickOps && on => ctx.notice(me, from.uid, format!("The bot will no longer kick channel operators in \x02{chan}\x02.")),
        Ok(()) if kicker == Kicker::DontKickOps => ctx.notice(me, from.uid, format!("The bot may again kick channel operators in \x02{chan}\x02.")),
        Ok(()) if on => ctx.notice(me, from.uid, format!("The \x02{}\x02 kicker is now on in \x02{chan}\x02.", label(kicker))),
        Ok(()) => ctx.notice(me, from.uid, format!("The \x02{}\x02 kicker is now off in \x02{chan}\x02.", label(kicker))),
        Err(_) => reg_error(me, from, chan, ctx),
    }
}

fn reg_error(me: &str, from: &Sender, chan: &str, ctx: &mut ServiceCtx) {
    ctx.notice(me, from.uid, format!("Couldn't update \x02{chan}\x02 — please try again in a moment."));
}
