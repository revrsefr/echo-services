use echo_api::{ForbidKind, NetView, ProfileField, Store};
use echo_api::{Sender, ServiceCtx};
use echo_api::t;

// SET PASSWORD <newpassword> | SET EMAIL [address]: change your account settings.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &mut dyn Store) {
    let Some(account) = from.account else {
        ctx.notice(me, from.uid, "You need to be logged in. Identify to NickServ first.");
        return;
    };
    let sub = args.get(1).map(|s| s.to_ascii_uppercase());
    // Credential/identity fields are owned by the website in external mode.
    if db.external_accounts() && matches!(sub.as_deref(), Some("PASSWORD" | "PASS" | "EMAIL")) {
        ctx.notice(me, from.uid, "That's managed on the website — change it there.");
        return;
    }
    match sub.as_deref() {
        Some("PASSWORD") | Some("PASS") => {
            let Some(&password) = args.get(2) else {
                ctx.notice(me, from.uid, "Syntax: SET PASSWORD <newpassword>");
                return;
            };
            if let Err(reason) = crate::password::validate_password(password, account) {
                ctx.notice(me, from.uid, reason);
                return;
            }
            // The link layer derives the new password off-thread, then commits it.
            ctx.defer_password(account, password, me, from.uid);
        }
        Some("EMAIL") => {
            let email = args.get(2).map(|s| s.to_string());
            let cleared = email.is_none();
            if let Some(addr) = &email {
                if !echo_api::valid_email(addr) {
                    ctx.notice(me, from.uid, "That doesn't look like a valid email address.");
                    return;
                }
                if db.is_forbidden(ForbidKind::Email, addr).is_some() {
                    ctx.notice(me, from.uid, "That email address is forbidden by network policy. Use a different one.");
                    return;
                }
            }
            match db.set_email(account, email) {
                Ok(()) if cleared => ctx.notice(me, from.uid, t!(ctx, "Email for \x02{account}\x02 cleared.", account = account)),
                Ok(()) => ctx.notice(me, from.uid, t!(ctx, "Email for \x02{account}\x02 updated.", account = account)),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        Some("LANGUAGE") | Some("LANG") => {
            let available = db.available_languages();
            match args.get(2) {
                None => {
                    let current = db.language_of(account).unwrap_or_else(|| db.default_language());
                    ctx.notice(me, from.uid, t!(ctx, "Your language is \x02{lang}\x02. Available: {list}. Change it with \x02SET LANGUAGE <code>\x02.", lang = current, list = available.join(", ")));
                }
                Some(&code) => {
                    let code = code.to_ascii_lowercase();
                    if !available.contains(&code) {
                        ctx.notice(me, from.uid, t!(ctx, "\x02{code}\x02 isn't an available language. Available: {list}.", code = code, list = available.join(", ")));
                        return;
                    }
                    match db.set_language(account, Some(code.clone())) {
                        // Confirm in the NEWLY chosen language, so it's visibly applied.
                        Ok(()) => ctx.notice(me, from.uid, echo_api::render(&code, "Your language is now \x02{lang}\x02.", &[("lang", code.clone())])),
                        Err(_) => ctx.notice(me, from.uid, t!(ctx, "Sorry, that didn't work. Please try again in a moment.")),
                    }
                }
            }
        }
        Some("HIDE") => {
            // Anope grammar is SET HIDE <field> {ON|OFF}. The only field that is
            // public here is the last-seen/online line (STATUS); USERMASK is an
            // accepted alias for it.
            match args.get(2).map(|s| s.to_ascii_uppercase()).as_deref() {
                Some("STATUS") | Some("USERMASK") => {
                    let Some(on) = args.get(3).and_then(|s| parse_toggle(s)) else {
                        let state = if db.account_hides_status(account) { "ON" } else { "OFF" };
                        ctx.notice(me, from.uid, t!(ctx, "HIDE STATUS is \x02{state}\x02. Syntax: SET HIDE STATUS {ON|OFF}", state = state));
                        return;
                    };
                    match db.set_account_hide_status(account, on) {
                        Ok(()) if on => ctx.notice(me, from.uid, "Your last-seen and online status are now hidden from other users."),
                        Ok(()) => ctx.notice(me, from.uid, "Your last-seen and online status are visible to everyone again."),
                        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
                    }
                }
                _ => ctx.notice(me, from.uid, "Syntax: SET HIDE STATUS {ON|OFF}"),
            }
        }
        Some("KILL") => {
            // Anope accepts ON/QUICK/IMMED/OFF; grace here is a fixed interval, so
            // the finer variants simply enable protection like ON.
            let on = match args.get(2).map(|s| s.to_ascii_uppercase()) {
                Some(v) if v == "ON" || v == "QUICK" || v == "IMMED" || v == "IMMEDIATE" => Some(true),
                Some(v) if v == "OFF" => Some(false),
                _ => None,
            };
            let Some(on) = on else {
                let state = if db.account_wants_protect(account) { "ON" } else { "OFF" };
                ctx.notice(me, from.uid, t!(ctx, "KILL (nick protection) is \x02{state}\x02. Syntax: SET KILL {ON|OFF}", state = state));
                return;
            };
            match db.set_account_kill(account, on) {
                Ok(()) if on => ctx.notice(me, from.uid, "Nick protection is \x02on\x02: someone using your nick without identifying will be renamed."),
                Ok(()) => ctx.notice(me, from.uid, "Nick protection is \x02off\x02: your registered nicks won't be enforced."),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        Some("AUTOOP") => {
            let Some(on) = args.get(2).and_then(|s| parse_toggle(s)) else {
                let state = if db.account_wants_autoop(account) { "ON" } else { "OFF" };
                ctx.notice(me, from.uid, t!(ctx, "AUTOOP is \x02{state}\x02. Syntax: SET AUTOOP {ON|OFF}", state = state));
                return;
            };
            match db.set_account_autoop(account, on) {
                Ok(()) if on => ctx.notice(me, from.uid, "You will be auto-opped where you have channel access."),
                Ok(()) => ctx.notice(me, from.uid, "You will no longer be auto-opped; op yourself with \x02/msg ChanServ UP\x02."),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        Some("SNOTICE") | Some("SNOTICES") => {
            let Some(on) = args.get(2).and_then(|s| parse_toggle(s)) else {
                let state = if db.account_wants_snotice(account) { "ON" } else { "OFF" };
                ctx.notice(me, from.uid, t!(ctx, "SNOTICE is \x02{state}\x02. Syntax: SET SNOTICE {ON|OFF}", state = state));
                return;
            };
            match db.set_account_snotice(account, on) {
                Ok(()) if on => ctx.notice(me, from.uid, "Service replies now arrive as server notices (\x02*** NickServ: …\x02)."),
                Ok(()) => ctx.notice(me, from.uid, "Service replies now arrive as normal notices from the service."),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        Some("GREET") => {
            // A bot shows this when you join a greet-enabled channel; no arg clears it.
            let greet = if args.len() > 2 { args[2..].join(" ") } else { String::new() };
            let cleared = greet.is_empty();
            match db.set_greet(account, &greet) {
                Ok(()) if cleared => ctx.notice(me, from.uid, "Your greet has been cleared."),
                Ok(()) => ctx.notice(me, from.uid, t!(ctx, "Your greet is now: {greet}", greet = greet)),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        Some("AVATAR") | Some("BIO") | Some("PRONOUNS") | Some("TIMEZONE") | Some("TZ") | Some("URL") | Some("WEBSITE") => {
            let field = ProfileField::parse(sub.as_deref().unwrap()).unwrap();
            // No value clears the field; otherwise the rest of the line is the value
            // (a bio can contain spaces).
            let value = if args.len() > 2 { Some(args[2..].join(" ")) } else { None };
            if let Some(v) = &value {
                if let Err(msg) = validate_profile(field, v) {
                    ctx.notice(me, from.uid, msg);
                    return;
                }
            }
            let label = field.meta_key();
            match db.set_profile(account, field, value.clone()) {
                Ok(()) => {
                    // Publish the change as IRCv3 metadata to every live session.
                    let mval = value.clone().unwrap_or_default();
                    for uid in net.uids_logged_into(account) {
                        ctx.metadata(&uid, field.meta_key(), &mval);
                    }
                    match &value {
                        Some(v) => ctx.notice(me, from.uid, t!(ctx, "Your {field} is now: {value}", field = label, value = v.clone())),
                        None => ctx.notice(me, from.uid, t!(ctx, "Your {field} has been cleared.", field = label)),
                    }
                }
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
        _ => ctx.notice(me, from.uid, "Syntax: SET PASSWORD <newpassword> | SET EMAIL [address] | SET GREET [message] | SET AVATAR [url] | SET BIO [text] | SET PRONOUNS [text] | SET TIMEZONE [tz] | SET URL [url] | SET AUTOOP {ON|OFF} | SET KILL {ON|OFF} | SET HIDE STATUS {ON|OFF} | SET SNOTICE {ON|OFF}"),
    }
}

// Validate a profile field value before it is stored and broadcast as metadata.
fn validate_profile(field: ProfileField, v: &str) -> Result<(), &'static str> {
    use echo_api::ProfileField::*;
    if v.chars().any(|c| c.is_control()) {
        return Err("That contains control characters — please remove them.");
    }
    let max = match field {
        Bio => 300,
        Pronouns => 40,
        Timezone => 64,
        Avatar | Url => 256,
    };
    if v.chars().count() > max {
        return Err("That's too long.");
    }
    if matches!(field, Avatar | Url)
        && (!(v.starts_with("https://") || v.starts_with("http://")) || v.contains(char::is_whitespace))
    {
        return Err("That must be a full http(s):// URL.");
    }
    Ok(())
}

fn parse_toggle(s: &str) -> Option<bool> {
    match s.to_ascii_uppercase().as_str() {
        "ON" | "TRUE" | "YES" => Some(true),
        "OFF" | "FALSE" | "NO" => Some(false),
        _ => None,
    }
}
