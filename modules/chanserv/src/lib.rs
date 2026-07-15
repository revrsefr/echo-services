use echo_api::{ChanError, ChannelView, Priv, Store};
use echo_api::{HelpEntry, Sender, Service, ServiceCtx};
use echo_api::NetView;

#[path = "mode.rs"]
mod mode;
#[path = "access.rs"]
mod access;
mod flags;
#[path = "op.rs"]
mod op;
#[path = "updown.rs"]
mod updown;
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
#[path = "suspend.rs"]
mod suspend;
mod noexpire;

const BLURB: &str = "ChanServ registers and looks after channels. Register a channel you hold ops in, then manage its access, modes, and topic.";

const TOPICS: &[HelpEntry] = &[
    HelpEntry { cmd: "REGISTER", summary: "register a channel", detail: "Syntax: \x02REGISTER <#channel>\x02\nRegisters a channel to you. You must currently hold ops in it." },
    HelpEntry { cmd: "INFO", summary: "show channel information", detail: "Syntax: \x02INFO <#channel>\x02\nShows a channel's registration and settings." },
    HelpEntry { cmd: "LIST", summary: "list registered channels", detail: "Syntax: \x02LIST\x02\nLists registered channels." },
    HelpEntry { cmd: "SET", summary: "change founder or settings", detail: "Syntax: \x02SET <#channel> FOUNDER <account> | DESC <text> | SUCCESSOR <account>|OFF | SIGNKICK|PRIVATE|PEACE|SECUREOPS|KEEPTOPIC|TOPICLOCK {ON|OFF}\x02\nTransfers the founder or changes a channel setting." },
    HelpEntry { cmd: "ACCESS", summary: "manage the access list", detail: "Syntax: \x02ACCESS <#channel> LIST | ADD <account> <op|voice> | DEL <account>\x02\nManages the channel access list." },
    HelpEntry { cmd: "FLAGS", summary: "granular per-account flags", detail: "Syntax: \x02FLAGS <#channel> [account [+/-flags]]\x02\nViews or changes granular per-account channel flags." },
    HelpEntry { cmd: "AOP/SOP/VOP", summary: "tiered access shortcuts", detail: "Syntax: \x02AOP|SOP|VOP <#channel> ADD <account> | DEL <account> | LIST\x02\nTiered shortcuts over ACCESS: AOP and SOP grant op, VOP grants voice." },
    HelpEntry { cmd: "STATUS", summary: "show a user's access", detail: "Syntax: \x02STATUS <#channel> [nick]\x02\nShows a user's access level on a channel." },
    HelpEntry { cmd: "OP/DEOP/VOICE/DEVOICE", summary: "give or take op/voice", detail: "Syntax: \x02OP|DEOP|VOICE|DEVOICE <#channel> [nick]\x02\nGives or takes channel op or voice." },
    HelpEntry { cmd: "UP/DOWN", summary: "apply or drop your status", detail: "Syntax: \x02UP|DOWN <#channel>\x02\nUP re-applies the op/voice your access entitles you to; DOWN removes your status." },
    HelpEntry { cmd: "OWNER/PROTECT/HALFOP", summary: "give or take higher status", detail: "Syntax: \x02OWNER|PROTECT|HALFOP <#channel> [nick]\x02 (and \x02DEOWNER|DEPROTECT|DEHALFOP\x02)\nSets +q/+a/+h. OWNER is founder-only; PROTECT and HALFOP need op access." },
    HelpEntry { cmd: "KICK", summary: "kick from the channel", detail: "Syntax: \x02KICK <#channel> <nick> [reason]\x02\nKicks a user from the channel." },
    HelpEntry { cmd: "BAN/UNBAN", summary: "ban or unban a user", detail: "Syntax: \x02BAN <#channel> <nick> [reason]\x02, \x02UNBAN <#channel> [nick]\x02\nBans or unbans a user by host." },
    HelpEntry { cmd: "AKICK", summary: "manage the auto-kick list", detail: "Syntax: \x02AKICK <#channel> ADD <mask> [reason] | DEL <mask> | LIST | CLEAR\x02\nManages the auto-kick list; matches are banned and kicked on join. CLEAR empties it." },
    HelpEntry { cmd: "ENFORCE", summary: "re-apply lock and access", detail: "Syntax: \x02ENFORCE <#channel>\x02\nRe-applies the mode-lock, access, and akick list to everyone present." },
    HelpEntry { cmd: "TOPIC", summary: "set the topic", detail: "Syntax: \x02TOPIC <#channel> <text>\x02\nSets the channel topic." },
    HelpEntry { cmd: "ENTRYMSG", summary: "message on join", detail: "Syntax: \x02ENTRYMSG <#channel> [CLEAR | <text>]\x02\nSets a message noticed to users as they join." },
    HelpEntry { cmd: "INVITE", summary: "invite into the channel", detail: "Syntax: \x02INVITE <#channel> [nick]\x02\nInvites you, or a nick, into the channel." },
    HelpEntry { cmd: "GETKEY", summary: "show the channel key", detail: "Syntax: \x02GETKEY <#channel>\x02\nShows the channel key (+k), if one is set." },
    HelpEntry { cmd: "SEEN", summary: "when a nick was last seen", detail: "Syntax: \x02SEEN <nick>\x02\nShows when a nick was last seen." },
    HelpEntry { cmd: "CLONE", summary: "copy channel settings", detail: "Syntax: \x02CLONE <source> <target>\x02\nCopies one channel's settings to another you own." },
    HelpEntry { cmd: "MODE", summary: "set channel modes", detail: "Syntax: \x02MODE <#channel> <modes>\x02\nSets modes on the channel, e.g. MODE #chan +nt." },
    HelpEntry { cmd: "MLOCK", summary: "lock channel modes", detail: "Syntax: \x02MLOCK <#channel> [modes]\x02\nLocks modes set or unset, e.g. MLOCK #chan +nt-s." },
    HelpEntry { cmd: "DROP", summary: "delete the registration", detail: "Syntax: \x02DROP <#channel>\x02\nDeletes the channel registration." },
    HelpEntry { cmd: "SUSPEND/UNSUSPEND", summary: "suspend a channel (operator)", detail: "Syntax: \x02SUSPEND <#channel> [+expiry] [reason]\x02, \x02UNSUSPEND <#channel>\x02\nSuspends or unsuspends a channel. Operators only." },
    HelpEntry { cmd: "NOEXPIRE", summary: "pin against expiry (operator)", detail: "Syntax: \x02NOEXPIRE <#channel> {ON|OFF}\x02\nPins a channel so inactivity expiry never drops it. Operators only." },
];

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

    fn help_topics(&self) -> (&'static str, &'static [HelpEntry]) {
        (BLURB, TOPICS)
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
                if db.channel_regs_frozen() {
                    ctx.notice(me, from.uid, "Channel registrations are temporarily frozen by network staff. Please try again later.");
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
                        ctx.count("chanserv.register");
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
                        ctx.notice(me, from.uid, format!("  Registered : {}", echo_api::human_time(info.ts)));
                        if let Some(s) = db.channel_suspension(chan) {
                            ctx.notice(me, from.uid, format!("  Suspended  : by \x02{}\x02 — {}", s.by, s.reason));
                        }
                        let mut opts = Vec::new();
                        if info.signkick { opts.push("SIGNKICK"); }
                        if info.private { opts.push("PRIVATE"); }
                        if info.peace { opts.push("PEACE"); }
                        if info.secureops { opts.push("SECUREOPS"); }
                        if info.keeptopic { opts.push("KEEPTOPIC"); }
                        if info.topiclock { opts.push("TOPICLOCK"); }
                        if !opts.is_empty() {
                            ctx.notice(me, from.uid, format!("  Options    : {}", opts.join(", ")));
                        }
                        // A staff note is shown to operators only.
                        if from.privs.has(Priv::Auspex) {
                            if let Some(note) = db.channel_note(chan) {
                                ctx.notice(me, from.uid, format!("  Staff note : {note}"));
                            }
                        }
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
                if suspended_block(me, from, chan, ctx, db) {
                    return;
                }
                match db.drop_channel(chan) {
                    Ok(()) => {
                        ctx.channel_mode(me, chan, "-r"); // no longer registered
                        ctx.count("chanserv.drop");
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
                if suspended_block(me, from, chan, ctx, db) {
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
            Some("FLAGS") => {
                let Some(&chan) = args.get(1) else {
                    ctx.notice(me, from.uid, "Syntax: FLAGS <#channel> [account [+/-flags]]");
                    return;
                };
                flags::handle(me, from, chan, args, ctx, db);
            }
            Some("OP") => op::handle(me, from, "+o", args, ctx, net, db),
            Some("DEOP") => op::handle(me, from, "-o", args, ctx, net, db),
            Some("VOICE") => op::handle(me, from, "+v", args, ctx, net, db),
            Some("DEVOICE") => op::handle(me, from, "-v", args, ctx, net, db),
            Some("UP") => updown::handle(me, from, true, args, ctx, net, db),
            Some("DOWN") => updown::handle(me, from, false, args, ctx, net, db),
            Some("OWNER") => op::handle(me, from, "+q", args, ctx, net, db),
            Some("DEOWNER") => op::handle(me, from, "-q", args, ctx, net, db),
            Some("PROTECT") | Some("ADMIN") => op::handle(me, from, "+a", args, ctx, net, db),
            Some("DEPROTECT") | Some("DEADMIN") => op::handle(me, from, "-a", args, ctx, net, db),
            Some("HALFOP") => op::handle(me, from, "+h", args, ctx, net, db),
            Some("DEHALFOP") => op::handle(me, from, "-h", args, ctx, net, db),
            Some("KICK") => kick::handle(me, from, args, ctx, net, db),
            Some("BAN") => ban::handle(me, from, args, ctx, net, db),
            Some("UNBAN") => unban::handle(me, from, args, ctx, net, db),
            Some("TOPIC") => topic::handle(me, from, args, ctx, db),
            Some("INVITE") => invite::handle(me, from, args, ctx, net, db),
            Some("AKICK") => akick::handle(me, from, args, ctx, db),
            Some("STATUS") => status::handle(me, from, args, ctx, net, db),
            Some("SUSPEND") => suspend::handle(me, from, args, ctx, net, db, true),
            Some("UNSUSPEND") => suspend::handle(me, from, args, ctx, net, db, false),
            Some("NOEXPIRE") => noexpire::handle(me, from, args, ctx, db),
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
            Some("HELP") => echo_api::help(me, from, ctx, BLURB, TOPICS, args.get(1).copied()),
            Some(other) => ctx.notice(me, from.uid, format!("I don't know the command \x02{other}\x02. Try \x02HELP\x02.")),
            None => {}
        }
    }
}

// True if `from` is the channel's founder; otherwise notices why and returns false.
fn require_founder(me: &str, from: &Sender, chan: &str, ctx: &mut ServiceCtx, db: &dyn Store) -> bool {
    if suspended_block(me, from, chan, ctx, db) {
        return false;
    }
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
    if suspended_block(me, from, chan, ctx, db) {
        return false;
    }
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

// A suspended channel is frozen: ChanServ won't manage it (returns true + notices).
fn suspended_block(me: &str, from: &Sender, chan: &str, ctx: &mut ServiceCtx, db: &dyn Store) -> bool {
    if db.is_channel_suspended(chan) {
        ctx.notice(me, from.uid, format!("\x02{chan}\x02 is suspended by network staff and can't be managed right now."));
        return true;
    }
    false
}

// PEACE: returns true (and notices) if `from` may not act against `target_uid`
// because the channel has PEACE set and the target holds equal-or-higher access.
fn peace_blocks(me: &str, from: &Sender, chan: &str, target_uid: &str, ctx: &mut ServiceCtx, net: &dyn NetView, db: &dyn Store) -> bool {
    let Some(info) = db.channel(chan) else { return false };
    if !info.peace {
        return false;
    }
    if info.access_rank(net.account_of(target_uid)) >= info.access_rank(from.account) {
        ctx.notice(me, from.uid, "\x02PEACE\x02 is set: you can't act against someone with equal or higher access.");
        return true;
    }
    false
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

