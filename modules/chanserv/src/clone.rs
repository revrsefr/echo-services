use echo_api::Store;
use echo_api::{Sender, ServiceCtx};

// CLONE <source> <target>: copy a channel's settings (mode lock, access,
// auto-kick, description, entry message) into another. Founder of both.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let (Some(&src), Some(&dest)) = (args.get(1), args.get(2)) else {
        ctx.notice(me, from.uid, "Syntax: CLONE <source> <target>");
        return;
    };
    let (Some(sinfo), Some(dinfo)) = (db.channel(src), db.channel(dest)) else {
        ctx.notice(me, from.uid, "Both channels must be registered.");
        return;
    };
    if from.account != Some(sinfo.founder.as_str()) || from.account != Some(dinfo.founder.as_str()) {
        ctx.notice(me, from.uid, "You must be the founder of both channels.");
        return;
    }
    let _ = db.set_mlock(dest, &sinfo.lock_on, &sinfo.lock_off, sinfo.lock_params.clone());
    for a in &sinfo.access {
        let _ = db.access_add(dest, &a.account, &a.level);
    }
    for k in &sinfo.akick {
        let _ = db.akick_add(dest, &k.mask, &k.reason);
        // Host-mask and passive-extban akicks are enforced only by a standing +b
        // (echo can't match them itself); place it as AKICK ADD does, or the cloned
        // entry sits inert on the target until someone runs ENFORCE.
        if echo_api::ircd_enforced(&k.mask) {
            ctx.channel_mode(me, dest, &format!("+b {}", k.mask));
        }
    }
    let _ = db.set_desc(dest, &sinfo.desc);
    let _ = db.set_entrymsg(dest, &sinfo.entrymsg);
    if let Some(info) = db.channel(dest) {
        ctx.channel_mode(me, dest, &info.lock_modes());
    }
    ctx.notice(me, from.uid, format!("Copied \x02{src}\x02's settings to \x02{dest}\x02."));
}
