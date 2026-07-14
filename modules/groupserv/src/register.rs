use echo_api::{Sender, ServiceCtx, Store};

// REGISTER <!group>: create a group with you as its founder.
pub fn handle(me: &str, from: &Sender, name: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(acc) = super::account(me, from, ctx) else { return };
    let Some(name) = name else {
        ctx.notice(me, from.uid, "Syntax: REGISTER <!group>");
        return;
    };
    if !name.starts_with('!') || name.len() < 2 {
        ctx.notice(me, from.uid, "A group name starts with \x02!\x02, e.g. \x02!staff\x02.");
        return;
    }
    let acc = acc.to_string();
    match db.group_register(name, &acc) {
        Ok(()) => ctx.notice(me, from.uid, format!("Group \x02{name}\x02 registered — you're the founder.")),
        Err(echo_api::ChanError::Exists) => ctx.notice(me, from.uid, format!("\x02{name}\x02 is already registered.")),
        Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
    }
}
