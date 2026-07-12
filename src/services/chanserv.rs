use crate::engine::db::{ChanError, ChannelInfo, Db};
use crate::engine::service::{Sender, Service, ServiceCtx};

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

    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut Db) {
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
                        ctx.notice(me, from.uid, format!("  Registered : {}", human_time(info.ts)));
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
                        Some(info) => ctx.notice(me, from.uid, format!("Mode lock for \x02{}\x02: \x02{}\x02", info.name, show_mlock(info))),
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
            Some("HELP") => ctx.notice(me, from.uid, "ChanServ registers and looks after channels. Commands: \x02REGISTER\x02 <#channel>, \x02INFO\x02 <#channel>, \x02MLOCK\x02 <#channel> [modes], \x02DROP\x02 <#channel>."),
            Some(other) => ctx.notice(me, from.uid, format!("I don't know the command \x02{other}\x02. Try \x02HELP\x02.")),
            None => {}
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
fn show_mlock(info: &ChannelInfo) -> String {
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

// Format a Unix timestamp (seconds) as "YYYY-MM-DD HH:MM:SS UTC", using Howard
// Hinnant's civil-from-days algorithm so no date crate is needed.
fn human_time(ts: u64) -> String {
    let days = (ts / 86400) as i64;
    let rem = ts % 86400;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02} {hh:02}:{mm:02}:{ss:02} UTC")
}

#[cfg(test)]
mod tests {
    use super::human_time;

    #[test]
    fn formats_unix_time_as_utc() {
        assert_eq!(human_time(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(human_time(1783844590), "2026-07-12 08:23:10 UTC");
    }
}
