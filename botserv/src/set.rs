use fedserv_api::{ChanSetting, Sender, ServiceCtx, Store};

// SET <#channel> <option> <on|off>: per-channel bot options. Founder-or-admin.
// Currently: GREET (show members' personal greets when they join).
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let (Some(&chan), Some(option)) = (args.get(1), args.get(2)) else {
        ctx.notice(me, from.uid, "Syntax: SET <#channel> GREET <ON|OFF>");
        return;
    };
    if !super::require_channel_admin(me, from, chan, ctx, db) {
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
        other => ctx.notice(me, from.uid, format!("Unknown option \x02{other}\x02. Available: \x02GREET\x02.")),
    }
}
