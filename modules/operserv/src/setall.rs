use echo_api::{ChanSetting, Priv, Sender, ServiceCtx, Store};

// SETALL <setting> <ON|OFF>: apply one channel on/off setting to EVERY registered
// channel at once — useful for rolling out a network-wide policy change. This
// overrides each channel's own choice, so it's admin-only and announced to staff.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — SETALL needs the \x02admin\x02 privilege.");
        return;
    }
    let syntax = "Syntax: SETALL <SECUREOPS|SECUREVOICES|PEACE|KEEPTOPIC|TOPICLOCK|RESTRICTED|PRIVATE> <ON|OFF>";
    let (Some(name), Some(state)) = (args.get(1), args.get(2)) else {
        ctx.notice(me, from.uid, syntax);
        return;
    };
    let setting = match name.to_ascii_uppercase().as_str() {
        "SECUREOPS" => ChanSetting::SecureOps,
        "SECUREVOICES" => ChanSetting::SecureVoices,
        "PEACE" => ChanSetting::Peace,
        "KEEPTOPIC" => ChanSetting::KeepTopic,
        "TOPICLOCK" => ChanSetting::TopicLock,
        "RESTRICTED" => ChanSetting::Restricted,
        "PRIVATE" => ChanSetting::Private,
        _ => {
            ctx.notice(me, from.uid, syntax);
            return;
        }
    };
    let on = match state.to_ascii_uppercase().as_str() {
        "ON" => true,
        "OFF" => false,
        _ => {
            ctx.notice(me, from.uid, syntax);
            return;
        }
    };
    let mut n = 0;
    for c in db.channels() {
        if db.set_channel_setting(&c.name, setting, on).is_ok() {
            n += 1;
        }
    }
    let up = name.to_ascii_uppercase();
    let word = if on { "on" } else { "off" };
    ctx.notice(me, from.uid, format!("Set \x02{up}\x02 \x02{word}\x02 on \x02{n}\x02 channel(s)."));
    ctx.alert("OPER", format!("SETALL {up} {word} on {n} channels"));
}
