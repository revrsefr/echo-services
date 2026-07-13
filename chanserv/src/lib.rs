use fedserv_api::{ChanError, ChannelView, Store};
use fedserv_api::{Sender, Service, ServiceCtx};
use fedserv_api::NetView;

#[path = "mode.rs"]
mod mode;
#[path = "access.rs"]
mod access;
#[path = "op.rs"]
mod op;
#[path = "kick.rs"]
mod kick;
#[path = "ban.rs"]
mod ban;
#[path = "unban.rs"]
mod unban;
#[path = "topic.rs"]
mod topic;
#[path = "invite.rs"]
mod invite;
#[path = "akick.rs"]
mod akick;
#[path = "list.rs"]
mod list;
#[path = "status.rs"]
mod status;
#[path = "set.rs"]
mod set;
#[path = "entrymsg.rs"]
mod entrymsg;
#[path = "getkey.rs"]
mod getkey;
#[path = "seen.rs"]
mod seen;
#[path = "enforce.rs"]
mod enforce;
#[path = "clone.rs"]
mod clone;
#[path = "xop.rs"]
mod xop;

pub struct ChanServ {
    pub uid: String,
}

impl Service for ChanServ {
    fn nick(&self) -> &str {
        "ChanServ"
    }
    fn uid(&self) -> &str {
        &self.uid
    }
    fn gecos(&self) -> &str {
        "Channel Services"
    }
    fn manages_channels(&self) -> bool {
        true
    }

    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, db: &mut dyn Store) {
        let me = self.uid.as_str();
        match args.first().map(|s| s.to_ascii_uppercase()).as_deref() {
            Some("REGISTER") => {
                let Some(&chan) = args.get(1) else {
                    ctx.notice(me, from.uid, "Syntax: REGISTER <#channel>");
                    return;
                };
                if !chan.starts_with('#') {
                    ctx.notice(me, from.uid, "Channel names start with \x02#\x02.");
                    return;
                }
                // The founder is the account the sender is identified to.
                let Some(account) = from.account else {
                    ctx.notice(me, from.uid, "You need to be logged in to register a channel. Identify to NickServ first.");
                    return;
                };
                // You can only register a channel you actually control right now.
                if !net.is_op(chan, from.uid) {
                    ctx.notice(me, from.uid, format!("You must be a channel operator (\x02@\x02) in \x02{chan}\x02 to register it."));
                    return;
                }
                match db.register_channel(chan, account) {
                    Ok(()) => {
                        ctx.channel_mode(me, chan, "+r"); // mark the channel registered
                        ctx.notice(me, from.uid, format!("\x02{chan}\x02 is now registered and you are its founder. Enjoy!"));
                    }
                    Err(ChanError::Exists) => ctx.notice(me, from.uid, format!("\x02{chan}\x02 is already registered. Try \x02INFO {chan}\x02 to see who owns it.")),
                    Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
                }
            }
            Some("INFO") => {
                let Some(&chan) = args.get(1) else {
                    ctx.notice(me, from.uid, "Syntax: INFO <#channel>");
                    return;
                };
                match db.channel(chan) {
                    Some(info) => {
                        ctx.notice(me, from.uid, format!("Information for \x02{}\x02:", info.name));
                        ctx.notice(me, from.uid, format!("  Founder    : \x02{}\x02", info.founder));
                        if !info.desc.is_empty() {
                            ctx.notice(me, from.uid, format!("  Description: {}", info.desc));
                        }
                        ctx.notice(me, from.uid, format!("  Registered : {}", fedserv_api::human_time(info.ts)));
                    }
                    None => ctx.notice(me, from.uid, format!("\x02{chan}\x02 isn't registered.")),
                }
            }
            Some("DROP") => {
                let Some(&chan) = args.get(1) else {
                    ctx.notice(me, from.uid, "Syntax: DROP <#channel>");
                    return;
                };
                // Read the founder, then drop, without holding the borrow across the mutation.
                let founder = match db.channel(chan) {
                    Some(info) => info.founder.clone(),
                    None => {
                        ctx.notice(me, from.uid, format!("\x02{chan}\x02 isn't registered."));
                        return;
                    }
                };
                if from.account != Some(founder.as_str()) {
                    ctx.notice(me, from.uid, format!("Only \x02{chan}\x02's founder can drop it."));
                    return;
                }
                match db.drop_channel(chan) {
                    Ok(()) => {
                        ctx.channel_mode(me, chan, "-r"); // no longer registered
                        ctx.notice(me, from.uid, format!("\x02{chan}\x02 has been dropped and is no longer registered."));
                    }
                    Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
                }
            }
            Some("MLOCK") => {
                let Some(&chan) = args.get(1) else {
                    ctx.notice(me, from.uid, "Syntax: MLOCK <#channel> [modes], e.g. MLOCK #chan +nt-s");
                    return;
                };
                // No modes given: show the current lock.
                if args.len() <= 2 {
                    match db.channel(chan) {
                        None => ctx.notice(me, from.uid, format!("\x02{chan}\x02 isn't registered.")),
                        Some(info) if info.lock_on.is_empty() && info.lock_off.is_empty() => {
                            ctx.notice(me, from.uid, format!("\x02{}\x02 has no mode lock set.", info.name));
                        }
                        Some(info) => ctx.notice(me, from.uid, format!("Mode lock for \x02{}\x02: \x02{}\x02", info.name, show_mlock(&info))),
                    }
                    return;
                }
                // Setting the lock: founder only.
                let founder = match db.channel(chan) {
                    Some(info) => info.founder.clone(),
                    None => {
                        ctx.notice(me, from.uid, format!("\x02{chan}\x02 isn't registered."));
                        return;
                    }
                };
                if from.account != Some(founder.as_str()) {
                    ctx.notice(me, from.uid, format!("Only \x02{chan}\x02's founder can set its mode lock."));
                    return;
                }
                let (on, off) = parse_mlock(&args[2..].concat());
                match db.set_mlock(chan, &on, &off) {
                    Ok(()) => {
                        if let Some(info) = db.channel(chan) {
                            ctx.channel_mode(me, chan, &info.lock_modes()); // apply it now
                        }
                        ctx.notice(me, from.uid, format!("Mode lock for \x02{chan}\x02 updated."));
                    }
                    Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
                }
            }
            Some("MODE") => mode::handle(me, from, args, ctx, db),
            Some("ACCESS") => access::handle(me, from, args, ctx, db),
            Some("OP") => op::handle(me, from, "+o", args, ctx, net, db),
            Some("DEOP") => op::handle(me, from, "-o", args, ctx, net, db),
            Some("VOICE") => op::handle(me, from, "+v", args, ctx, net, db),
            Some("DEVOICE") => op::handle(me, from, "-v", args, ctx, net, db),
            Some("KICK") => kick::handle(me, from, args, ctx, net, db),
            Some("BAN") => ban::handle(me, from, args, ctx, net, db),
            Some("UNBAN") => unban::handle(me, from, args, ctx, net, db),
            Some("TOPIC") => topic::handle(me, from, args, ctx, db),
            Some("INVITE") => invite::handle(me, from, args, ctx, net, db),
            Some("AKICK") => akick::handle(me, from, args, ctx, db),
            Some("STATUS") => status::handle(me, from, args, ctx, net, db),
            Some("LIST") => list::handle(me, from, args, ctx, db),
            Some("SET") => set::handle(me, from, args, ctx, db),
            Some("ENTRYMSG") => entrymsg::handle(me, from, args, ctx, db),
            Some("GETKEY") => getkey::handle(me, from, args, ctx, net, db),
            Some("SEEN") => seen::handle(me, from, args, ctx, net),
            Some("ENFORCE") => enforce::handle(me, from, args, ctx, net, db),
            Some("CLONE") => clone::handle(me, from, args, ctx, db),
            Some("AOP") => xop::handle(me, from, "AOP", "op", args, ctx, db),
            Some("SOP") => xop::handle(me, from, "SOP", "op", args, ctx, db),
            Some("VOP") => xop::handle(me, from, "VOP", "voice", args, ctx, db),
            Some("HELP") => ctx.notice(me, from.uid, "ChanServ registers and looks after channels. Commands: \x02REGISTER\x02, \x02INFO\x02, \x02LIST\x02, \x02SET\x02, \x02ACCESS\x02, \x02AOP\x02/\x02SOP\x02/\x02VOP\x02, \x02STATUS\x02, \x02OP\x02/\x02DEOP\x02, \x02VOICE\x02/\x02DEVOICE\x02, \x02KICK\x02, \x02BAN\x02/\x02UNBAN\x02, \x02AKICK\x02, \x02ENFORCE\x02, \x02TOPIC\x02, \x02ENTRYMSG\x02, \x02INVITE\x02, \x02GETKEY\x02, \x02SEEN\x02, \x02CLONE\x02, \x02MODE\x02, \x02MLOCK\x02, \x02DROP\x02."),
            Some(other) => ctx.notice(me, from.uid, format!("I don't know the command \x02{other}\x02. Try \x02HELP\x02.")),
            None => {}
        }
    }
}

// True if `from` is the channel's founder; otherwise notices why and returns false.
fn require_founder(me: &str, from: &Sender, chan: &str, ctx: &mut ServiceCtx, db: &dyn Store) -> bool {
    match db.channel(chan) {
        None => {
            ctx.notice(me, from.uid, format!("\x02{chan}\x02 isn't registered."));
            false
        }
        Some(info) if from.account == Some(info.founder.as_str()) => true,
        _ => {
            ctx.notice(me, from.uid, format!("Only \x02{chan}\x02's founder can do that."));
            false
        }
    }
}

// True if `from` is the founder or an access-list op of `chan`; else notices why.
fn require_op(me: &str, from: &Sender, chan: &str, ctx: &mut ServiceCtx, db: &dyn Store) -> bool {
    match (from.account, db.channel(chan)) {
        (_, None) => {
            ctx.notice(me, from.uid, format!("\x02{chan}\x02 isn't registered."));
            false
        }
        (Some(acc), Some(info)) if info.is_op(acc) => true,
        _ => {
            ctx.notice(me, from.uid, format!("You need operator access to \x02{chan}\x02."));
            false
        }
    }
}

// Parse a mode spec like "+nt-s" into (locked-on, locked-off) mode chars. `r` is
// implicit for a registered channel and is ignored here.
fn parse_mlock(spec: &str) -> (String, String) {
    let (mut on, mut off) = (String::new(), String::new());
    let mut adding = true;
    for ch in spec.chars() {
        match ch {
            '+' => adding = true,
            '-' => adding = false,
            'r' => {}
            m if m.is_ascii_alphabetic() => {
                on.retain(|c| c != m);
                off.retain(|c| c != m);
                if adding {
                    on.push(m);
                } else {
                    off.push(m);
                }
            }
            _ => {}
        }
    }
    (on, off)
}

// Render a channel's lock as "+on-off" for display.
fn show_mlock(info: &ChannelView) -> String {
    let mut s = String::new();
    if !info.lock_on.is_empty() {
        s.push('+');
        s.push_str(&info.lock_on);
    }
    if !info.lock_off.is_empty() {
        s.push('-');
        s.push_str(&info.lock_off);
    }
    s
}

