use echo_api::Store;
use echo_api::{Sender, ServiceCtx};

// MODE <#channel> <modes>: the founder sets channel modes via ChanServ. Extban
// arguments on the ban-family list modes (+b/+e/+I) are held to the same
// `[extban] enabled` policy as AKICK; everything else passes to the ircd as-is.
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
    // Reject an extban the network has turned off, before relaying anything.
    for mask in ban_masks(&args[2..], |m, adding| db.chanmode_takes_param(m, adding)) {
        let core = mask.strip_prefix('!').unwrap_or(mask); // extbans may be inverted
        if let echo_api::AkickMask::Ext(eb, _) = echo_api::AkickMask::parse(core) {
            if !db.extban_offered(eb.name) {
                ctx.notice(me, from.uid, format!("This network's ircd doesn't offer the \x02{}\x02 extban.", eb.name));
                return;
            }
            if !db.extban_enabled(eb.name) {
                ctx.notice(me, from.uid, format!("The \x02{}\x02 extban isn't enabled on this network.", eb.name));
                return;
            }
        }
    }
    let modes = args[2..].join(" ");
    ctx.channel_mode(me, chan, &modes);
    ctx.notice(me, from.uid, format!("Set \x02{modes}\x02 on \x02{chan}\x02."));
}

// The parameters attached to +b/-b/+e/-e/+I/-I in a `<modes> [params...]` change.
// `takes_param` (the ircd's advertised arity) accounts for every param-taking mode
// so ban masks pair to the right mode in IRC order.
fn ban_masks<'a>(tokens: &'a [&'a str], takes_param: impl Fn(char, bool) -> bool) -> Vec<&'a str> {
    let modes = tokens.first().copied().unwrap_or("");
    let mut params = tokens.iter().skip(1);
    let mut adding = true;
    let mut out = Vec::new();
    for ch in modes.chars() {
        match ch {
            '+' => adding = true,
            '-' => adding = false,
            m if takes_param(m, adding) => {
                if let Some(&p) = params.next() {
                    if matches!(m, 'b' | 'e' | 'I') {
                        out.push(p);
                    }
                }
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::ban_masks;

    #[test]
    fn ban_masks_pairs_params_in_mode_order() {
        // A lone ban, and a ban after a prefix mode: the mask must pair to +b.
        assert_eq!(ban_masks(&["+b", "account:x"], echo_api::chanmode_takes_param), ["account:x"]);
        assert_eq!(ban_masks(&["+ob", "nick", "account:x"], echo_api::chanmode_takes_param), ["account:x"]);
        // The key's value is not a ban mask even when it looks like an extban.
        assert!(ban_masks(&["+k", "account:secret"], echo_api::chanmode_takes_param).is_empty());
        // Exceptions and invex count; plain flag modes carry nothing.
        assert_eq!(ban_masks(&["+eI", "R:a", "r:b"], echo_api::chanmode_takes_param), ["R:a", "r:b"]);
        assert!(ban_masks(&["+nt"], echo_api::chanmode_takes_param).is_empty());
        // Removal still carries a mask.
        assert_eq!(ban_masks(&["-b", "*!*@h"], echo_api::chanmode_takes_param), ["*!*@h"]);
    }
}
