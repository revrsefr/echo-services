use echo_api::{ChanSetting, Sender, ServiceCtx, Store};

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
    if super::suspended_block(me, from, chan, ctx, db) {
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
        Some("SUCCESSOR") => {
            match args.get(3) {
                Some(&acct) if !acct.eq_ignore_ascii_case("OFF") => {
                    if !db.exists(acct) {
                        ctx.notice(me, from.uid, format!("\x02{acct}\x02 isn't a registered account."));
                        return;
                    }
                    if acct.eq_ignore_ascii_case(&founder) {
                        ctx.notice(me, from.uid, "The successor must be someone other than the founder.");
                        return;
                    }
                    match db.set_successor(chan, Some(acct)) {
                        Ok(()) => ctx.notice(me, from.uid, format!("Successor of \x02{chan}\x02 set to \x02{acct}\x02. They inherit it if your account is dropped or expires.")),
                        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
                    }
                }
                _ => match db.set_successor(chan, None) {
                    Ok(()) => ctx.notice(me, from.uid, format!("Successor of \x02{chan}\x02 cleared.")),
                    Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
                },
            }
        }
        Some("DESC") => {
            let desc = if args.len() > 3 { args[3..].join(" ") } else { String::new() };
            match db.set_desc(chan, &desc) {
                Ok(()) => ctx.notice(me, from.uid, format!("Description for \x02{chan}\x02 updated.")),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        Some("SIGNKICK") => toggle(me, from, ctx, db, chan, ChanSetting::SignKick, args.get(3).copied()),
        Some("PRIVATE") => toggle(me, from, ctx, db, chan, ChanSetting::Private, args.get(3).copied()),
        Some("PEACE") => toggle(me, from, ctx, db, chan, ChanSetting::Peace, args.get(3).copied()),
        Some("SECUREOPS") => toggle(me, from, ctx, db, chan, ChanSetting::SecureOps, args.get(3).copied()),
        Some("RESTRICTED") => toggle(me, from, ctx, db, chan, ChanSetting::Restricted, args.get(3).copied()),
        Some("KEEPTOPIC") => toggle(me, from, ctx, db, chan, ChanSetting::KeepTopic, args.get(3).copied()),
        Some("TOPICLOCK") => toggle(me, from, ctx, db, chan, ChanSetting::TopicLock, args.get(3).copied()),
        _ => ctx.notice(me, from.uid, "Syntax: SET <#channel> FOUNDER <account> | SUCCESSOR <account>|OFF | DESC <text> | SIGNKICK {ON|OFF} | PRIVATE {ON|OFF} | PEACE {ON|OFF} | SECUREOPS {ON|OFF} | RESTRICTED {ON|OFF} | KEEPTOPIC {ON|OFF} | TOPICLOCK {ON|OFF}"),
    }
}

// The SET keyword for a channel option, used in its messages.
fn label(setting: ChanSetting) -> &'static str {
    match setting {
        ChanSetting::SignKick => "SIGNKICK",
        ChanSetting::Private => "PRIVATE",
        ChanSetting::Peace => "PEACE",
        ChanSetting::SecureOps => "SECUREOPS",
        ChanSetting::Restricted => "RESTRICTED",
        ChanSetting::KeepTopic => "KEEPTOPIC",
        ChanSetting::TopicLock => "TOPICLOCK",
        ChanSetting::BotGreet => "GREET",
        ChanSetting::NoBot => "NOBOT",
    }
}

// Flip one on/off channel option, reporting the new state.
fn toggle(me: &str, from: &Sender, ctx: &mut ServiceCtx, db: &mut dyn Store, chan: &str, setting: ChanSetting, arg: Option<&str>) {
    let name = label(setting);
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
