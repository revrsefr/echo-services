use fedserv_api::Store;
use fedserv_api::{Sender, ServiceCtx};

// MODE <#channel> <modes>: the founder sets channel modes via ChanServ.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    let Some(&chan) = args.get(1) else {
        ctx.notice(me, from.uid, "Syntax: MODE <#channel> <modes>, e.g. MODE #chan +nt");
        return;
    };
    if args.len() <= 2 {
        ctx.notice(me, from.uid, "Syntax: MODE <#channel> <modes>, e.g. MODE #chan +nt");
        return;
    }
    let founder = match db.channel(chan) {
        Some(info) => info.founder.clone(),
        None => {
            ctx.notice(me, from.uid, format!("\x02{chan}\x02 isn't registered."));
            return;
        }
    };
    if from.account != Some(founder.as_str()) {
        ctx.notice(me, from.uid, format!("Only \x02{chan}\x02's founder can change its modes."));
        return;
    }
    let modes = args[2..].join(" ");
    ctx.channel_mode(me, chan, &modes);
    ctx.notice(me, from.uid, format!("Set \x02{modes}\x02 on \x02{chan}\x02."));
}
