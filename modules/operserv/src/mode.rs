use echo_api::{NetView, Priv, Sender, ServiceCtx, Store};

// MODE <#channel> <modes> [params]: set channel modes as a services override
// (forced, so it applies regardless of the current TS). Admin-only. Status-mode
// targets may be given as nicks — they're resolved to uids for the ircd.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &dyn Store) {
    if !from.privs.has(Priv::Admin) {
        ctx.notice(me, from.uid, "Access denied — MODE needs the \x02admin\x02 privilege.");
        return;
    }
    let Some(&chan) = args.get(1).filter(|c| c.starts_with('#') || c.starts_with('&')) else {
        ctx.notice(me, from.uid, "Syntax: MODE <#channel> <modes> [params]");
        return;
    };
    let Some(&modes) = args.get(2) else {
        ctx.notice(me, from.uid, "Syntax: MODE <#channel> <modes> [params]");
        return;
    };
    let params = &args[3..];

    // Walk the change alongside its params: each param-taking mode consumes one,
    // and a status mode's param is a nick we translate to its uid. Both arity and
    // the prefix set come from the ircd's advertised CHANMODES (incl custom modes).
    let status_modes = db.status_modes();
    let (mut adding, mut pi) = (true, 0);
    let mut out_params: Vec<String> = Vec::new();
    for m in modes.chars() {
        match m {
            '+' => adding = true,
            '-' => adding = false,
            _ if db.chanmode_takes_param(m, adding) => {
                if let Some(&p) = params.get(pi) {
                    pi += 1;
                    if status_modes.contains(m) {
                        out_params.push(net.uid_by_nick(p).map(str::to_string).unwrap_or_else(|| p.to_string()));
                    } else {
                        out_params.push(p.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    let full = if out_params.is_empty() { modes.to_string() } else { format!("{} {}", modes, out_params.join(" ")) };
    ctx.channel_mode(me, chan, &full);
    ctx.notice(me, from.uid, format!("Set \x02{modes}\x02 on \x02{chan}\x02."));
}
