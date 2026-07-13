use fedserv_api::{ChanSetting, Sender, ServiceCtx, Store};

// SET <#channel> FOUNDER <account> | DESC <text>: founder-only channel settings.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(&chan) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: SET <#channel> FOUNDER <account> | DESC <text>");
        return;
    };
    let founder = match db.channel(chan) {
        None => {
            ctx.notice(me, from.uid, format!("\x02{chan}\x02 isn't registered."));
            return;
        }
        Some(info) => info.founder.clone(),
    };
    if from.account != Some(founder.as_str()) {
        ctx.notice(me, from.uid, format!("Only \x02{chan}\x02's founder can change its settings."));
        return;
    }
    match args.get(2).map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("FOUNDER") => {
            let Some(&account) = args.get(3) else {
                ctx.notice(me, from.uid, "Syntax: SET <#channel> FOUNDER <account>");
                return;
            };
            if !db.exists(account) {
                ctx.notice(me, from.uid, format!("\x02{account}\x02 isn't a registered account."));
                return;
            }
            match db.set_founder(chan, account) {
                Ok(()) => ctx.notice(me, from.uid, format!("Founder of \x02{chan}\x02 transferred to \x02{account}\x02.")),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        Some("DESC") => {
            let desc = if args.len() > 3 { args[3..].join(" ") } else { String::new() };
            match db.set_desc(chan, &desc) {
                Ok(()) => ctx.notice(me, from.uid, format!("Description for \x02{chan}\x02 updated.")),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        Some("SIGNKICK") => toggle(me, from, ctx, db, chan, ChanSetting::SignKick, args.get(3).copied(), "SIGNKICK"),
        Some("PRIVATE") => toggle(me, from, ctx, db, chan, ChanSetting::Private, args.get(3).copied(), "PRIVATE"),
        Some("PEACE") => toggle(me, from, ctx, db, chan, ChanSetting::Peace, args.get(3).copied(), "PEACE"),
        Some("SECUREOPS") => toggle(me, from, ctx, db, chan, ChanSetting::SecureOps, args.get(3).copied(), "SECUREOPS"),
        _ => ctx.notice(me, from.uid, "Syntax: SET <#channel> FOUNDER <account> | DESC <text> | SIGNKICK {ON|OFF} | PRIVATE {ON|OFF} | PEACE {ON|OFF} | SECUREOPS {ON|OFF}"),
    }
}

// Flip one on/off channel option, reporting the new state.
fn toggle(me: &str, from: &Sender, ctx: &mut ServiceCtx, db: &mut dyn Store, chan: &str, setting: ChanSetting, arg: Option<&str>, name: &str) {
    let on = match arg.map(|s| s.to_ascii_uppercase()).as_deref() {
        Some("ON") => true,
        Some("OFF") => false,
        _ => {
            ctx.notice(me, from.uid, format!("Syntax: SET <#channel> {name} {{ON|OFF}}"));
            return;
        }
    };
    match db.set_channel_setting(chan, setting, on) {
        Ok(()) => ctx.notice(me, from.uid, format!("\x02{name}\x02 for \x02{chan}\x02 is now \x02{}\x02.", if on { "on" } else { "off" })),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
