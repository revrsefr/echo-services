use echo_api::{ChanSetting, NetView, Sender, ServiceCtx, Store};
use echo_api::t;

// SET <#channel> FOUNDER <account> | DESC <text>: founder-only channel settings.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &mut dyn Store) {
    let Some(&chan) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: SET <#channel> FOUNDER <account> | DESC <text>");
        return;
    };
    let founder = match db.channel(chan) {
        None => {
            ctx.notice(me, from.uid, t!(ctx, "\x02{chan}\x02 isn't registered.", chan = chan));
            return;
        }
        Some(info) => info.founder.clone(),
    };
    if from.account != Some(founder.as_str()) {
        ctx.notice(me, from.uid, t!(ctx, "Only \x02{chan}\x02's founder can change its settings.", chan = chan));
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
                ctx.notice(me, from.uid, t!(ctx, "\x02{account}\x02 isn't a registered account.", account = account));
                return;
            }
            match db.set_founder(chan, account) {
                Ok(()) => {
                    ctx.notice(me, from.uid, t!(ctx, "Founder of \x02{chan}\x02 transferred to \x02{account}\x02.", chan = chan, account = account));
                    let by = from.account.unwrap_or(from.nick);
                    echo_api::notify_or_memo(ctx, net, db, me, by, account, "\x02{by}\x02 transferred the \x02{chan}\x02 founder to you.", &[("by", by.to_string()), ("chan", chan.to_string())]);
                }
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        Some("SUCCESSOR") => {
            match args.get(3) {
                Some(&acct) if !acct.eq_ignore_ascii_case("OFF") => {
                    if !db.exists(acct) {
                        ctx.notice(me, from.uid, t!(ctx, "\x02{account}\x02 isn't a registered account.", account = acct));
                        return;
                    }
                    if acct.eq_ignore_ascii_case(&founder) {
                        ctx.notice(me, from.uid, "The successor must be someone other than the founder.");
                        return;
                    }
                    match db.set_successor(chan, Some(acct)) {
                        Ok(()) => {
                            ctx.notice(me, from.uid, t!(ctx, "Successor of \x02{chan}\x02 set to \x02{acct}\x02. They inherit it if your account is dropped or expires.", chan = chan, acct = acct));
                            let by = from.account.unwrap_or(from.nick);
                            echo_api::notify_or_memo(ctx, net, db, me, by, acct, "\x02{by}\x02 set you as successor of \x02{chan}\x02.", &[("by", by.to_string()), ("chan", chan.to_string())]);
                        }
                        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
                    }
                }
                _ => match db.set_successor(chan, None) {
                    Ok(()) => ctx.notice(me, from.uid, t!(ctx, "Successor of \x02{chan}\x02 cleared.", chan = chan)),
                    Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
                },
            }
        }
        Some("DESC") => {
            let desc = if args.len() > 3 { args[3..].join(" ") } else { String::new() };
            match db.set_desc(chan, &desc) {
                Ok(()) => ctx.notice(me, from.uid, t!(ctx, "Description for \x02{chan}\x02 updated.", chan = chan)),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        Some("URL") => {
            let url = if args.len() > 3 { args[3..].join(" ") } else { String::new() };
            match db.set_url(chan, &url) {
                Ok(()) if url.is_empty() => ctx.notice(me, from.uid, t!(ctx, "URL for \x02{chan}\x02 cleared.", chan = chan)),
                Ok(()) => ctx.notice(me, from.uid, t!(ctx, "URL for \x02{chan}\x02 updated.", chan = chan)),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        Some("EMAIL") => {
            let email = args.get(3).copied().unwrap_or("");
            match db.set_channel_email(chan, email) {
                Ok(()) if email.is_empty() => ctx.notice(me, from.uid, t!(ctx, "Contact email for \x02{chan}\x02 cleared.", chan = chan)),
                Ok(()) => ctx.notice(me, from.uid, t!(ctx, "Contact email for \x02{chan}\x02 updated.", chan = chan)),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        Some("SIGNKICK") => toggle(me, from, ctx, db, chan, ChanSetting::SignKick, args.get(3).copied()),
        Some("PRIVATE") => toggle(me, from, ctx, db, chan, ChanSetting::Private, args.get(3).copied()),
        Some("PEACE") => toggle(me, from, ctx, db, chan, ChanSetting::Peace, args.get(3).copied()),
        Some("SECUREOPS") => toggle(me, from, ctx, db, chan, ChanSetting::SecureOps, args.get(3).copied()),
        Some("SECUREVOICES") => toggle(me, from, ctx, db, chan, ChanSetting::SecureVoices, args.get(3).copied()),
        Some("RESTRICTED") => toggle(me, from, ctx, db, chan, ChanSetting::Restricted, args.get(3).copied()),
        Some("AUTOOP") => toggle(me, from, ctx, db, chan, ChanSetting::AutoOp, args.get(3).copied()),
        Some("KEEPTOPIC") => toggle(me, from, ctx, db, chan, ChanSetting::KeepTopic, args.get(3).copied()),
        Some("TOPICLOCK") => toggle(me, from, ctx, db, chan, ChanSetting::TopicLock, args.get(3).copied()),
        _ => ctx.notice(me, from.uid, "Syntax: SET <#channel> FOUNDER <account> | SUCCESSOR <account>|OFF | DESC <text> | URL [address] | EMAIL [address] | SIGNKICK {ON|OFF} | PRIVATE {ON|OFF} | PEACE {ON|OFF} | SECUREOPS {ON|OFF} | SECUREVOICES {ON|OFF} | RESTRICTED {ON|OFF} | AUTOOP {ON|OFF} | KEEPTOPIC {ON|OFF} | TOPICLOCK {ON|OFF}"),
    }
}

// The SET keyword for a channel option, used in its messages.
fn label(setting: ChanSetting) -> &'static str {
    match setting {
        ChanSetting::SignKick => "SIGNKICK",
        ChanSetting::Private => "PRIVATE",
        ChanSetting::Peace => "PEACE",
        ChanSetting::SecureOps => "SECUREOPS",
        ChanSetting::SecureVoices => "SECUREVOICES",
        ChanSetting::Restricted => "RESTRICTED",
        ChanSetting::AutoOp => "AUTOOP",
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
            ctx.notice(me, from.uid, t!(ctx, "Syntax: SET <#channel> {name} {ON|OFF}", name = name));
            return;
        }
    };
    match db.set_channel_setting(chan, setting, on) {
        Ok(()) => ctx.notice(me, from.uid, t!(ctx, "\x02{name}\x02 for \x02{chan}\x02 is now \x02{state}\x02.", name = name, chan = chan, state = if on { "on" } else { "off" })),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
