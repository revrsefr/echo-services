use echo_api::{parse_duration, t, Priv, Sender, ServiceCtx, Store, XlineKind};
use std::time::{SystemTime, UNIX_EPOCH};

// A network-ban command family (AKILL, SQLINE, …): the ircd X-line `kind`, the
// user-facing command `name`, and the mask shape it accepts. One implementation
// drives ADD / DEL / LIST for every kind so they stay consistent.
pub struct Xline {
    pub kind: XlineKind,
    pub name: &'static str,
    pub target: &'static str, // e.g. "user@host" or "nick" — shown in syntax
    pub normalize: fn(&str) -> Option<String>,
}

impl Xline {
    pub fn handle(&self, me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
        if !from.privs.has(Priv::Oper) {
            ctx.notice(me, from.uid, t!(ctx, "Access denied — {name} needs the \x02operator\x02 privilege.", name = self.name));
            return;
        }
        match args.get(1).map(|s| s.to_ascii_uppercase()).as_deref() {
            Some("ADD") => self.add(me, from, &args[2..], ctx, db),
            Some("DEL") | Some("REMOVE") => self.del(me, from, args.get(2).copied(), ctx, db),
            Some("LIST") | Some("VIEW") => self.list(me, from, args.get(2).copied(), ctx, db),
            _ => ctx.notice(me, from.uid, t!(ctx, "Syntax: {name} ADD [+expiry] <{target}> <reason> | {name} DEL <{target}|number> | {name} LIST [pattern]", name = self.name, target = self.target)),
        }
    }

    fn add(&self, me: &str, from: &Sender, rest: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
        // An optional leading +duration, then the mask, then a free-text reason.
        let mut rest = rest;
        let duration = rest.first().and_then(|t| t.strip_prefix('+')).and_then(parse_duration);
        if duration.is_some() {
            rest = &rest[1..];
        }
        let Some((&raw, reason_words)) = rest.split_first() else {
            ctx.notice(me, from.uid, t!(ctx, "Syntax: {name} ADD [+expiry] <{target}> <reason>", name = self.name, target = self.target));
            return;
        };
        let Some(mask) = (self.normalize)(raw) else {
            ctx.notice(me, from.uid, t!(ctx, "\x02{raw}\x02 isn't a valid \x02{target}\x02 mask.", raw = raw, target = self.target));
            return;
        };
        if reason_words.is_empty() {
            ctx.notice(me, from.uid, "Please give a reason.");
            return;
        }
        if too_wide(&mask, self.kind == XlineKind::Rline) {
            ctx.notice(me, from.uid, "That mask is too wide — it would match almost everyone.");
            return;
        }
        let reason = reason_words.join(" ");
        let setter = from.account.unwrap_or(from.nick);
        let expires = duration.map(|secs| now() + secs);
        match db.akill_add(self.kind, &mask, setter, &reason, expires) {
            Ok(fresh) => {
                ctx.add_line(self.kind, &mask, from.nick, duration.unwrap_or(0), &reason);
                let msg = match (fresh, expires.is_some()) {
                    (true, true) => t!(ctx, "{name} added for \x02{mask}\x02 (temporary).", name = self.name, mask = mask),
                    (true, false) => t!(ctx, "{name} added for \x02{mask}\x02.", name = self.name, mask = mask),
                    (false, true) => t!(ctx, "{name} updated for \x02{mask}\x02 (temporary).", name = self.name, mask = mask),
                    (false, false) => t!(ctx, "{name} updated for \x02{mask}\x02.", name = self.name, mask = mask),
                };
                ctx.notice(me, from.uid, msg);
            }
            Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
        }
    }

    fn del(&self, me: &str, from: &Sender, arg: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
        let Some(arg) = arg else {
            ctx.notice(me, from.uid, t!(ctx, "Syntax: {name} DEL <{target}|number>", name = self.name, target = self.target));
            return;
        };
        // A number targets the nth entry of this kind in the list; else a mask.
        let mask = match arg.parse::<usize>() {
            Ok(n) if n >= 1 => match self.mine(db).get(n - 1) {
                Some(mask) => mask.clone(),
                None => {
                    ctx.notice(me, from.uid, t!(ctx, "There's no {name} number \x02{n}\x02.", name = self.name, n = n));
                    return;
                }
            },
            _ => (self.normalize)(arg).unwrap_or_else(|| arg.to_string()),
        };
        match db.akill_del(self.kind, &mask) {
            Ok(true) => {
                ctx.del_line(self.kind, &mask);
                ctx.notice(me, from.uid, t!(ctx, "{name} for \x02{mask}\x02 removed.", name = self.name, mask = mask));
            }
            Ok(false) => ctx.notice(me, from.uid, t!(ctx, "No {name} matches \x02{mask}\x02.", name = self.name, mask = mask)),
            Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
        }
    }

    fn list(&self, me: &str, from: &Sender, pattern: Option<&str>, ctx: &mut ServiceCtx, db: &mut dyn Store) {
        let pat = pattern.map(|p| p.to_ascii_lowercase());
        let mut shown = 0;
        for (i, a) in db.akills().iter().filter(|a| a.kind == self.kind).enumerate() {
            if let Some(p) = &pat {
                if !a.mask.to_ascii_lowercase().contains(p.as_str()) {
                    continue;
                }
            }
            let msg = match a.expires {
                Some(e) => t!(ctx, "{n}. \x02{mask}\x02 by {setter} — {reason}, expires in {ttl}", n = i + 1, mask = a.mask, setter = a.setter, reason = a.reason, ttl = human_secs(e.saturating_sub(now()))),
                None => t!(ctx, "{n}. \x02{mask}\x02 by {setter} — {reason}", n = i + 1, mask = a.mask, setter = a.setter, reason = a.reason),
            };
            ctx.notice(me, from.uid, msg);
            shown += 1;
        }
        if shown == 0 {
            ctx.notice(me, from.uid, t!(ctx, "No matching {name} entries.", name = self.name));
        } else {
            ctx.notice(me, from.uid, t!(ctx, "End of {name} list ({shown} shown).", name = self.name, shown = shown));
        }
    }

    // The live masks of this kind, in list order (for DEL by number).
    fn mine(&self, db: &dyn Store) -> Vec<String> {
        db.akills().into_iter().filter(|a| a.kind == self.kind).map(|a| a.mask).collect()
    }
}

// AKILL: a user@host G-line. Strips any nick! prefix, lowercases both sides.
pub const AKILL: Xline = Xline { kind: XlineKind::Gline, name: "AKILL", target: "user@host", normalize: norm_userhost };

// SQLINE: a nick Q-line. The mask is a nick glob (no '@'); wildcards allowed.
pub const SQLINE: Xline = Xline { kind: XlineKind::Qline, name: "SQLINE", target: "nick", normalize: norm_nick };

// SNLINE: a realname R-line. The mask is a regex the ircd matches against a
// connecting user's realname (use `.` for spaces, e.g. `.*free.money.*`).
pub const SNLINE: Xline = Xline { kind: XlineKind::Rline, name: "SNLINE", target: "realname-regex", normalize: norm_realname };

// SHUN: a user@host shun. A matching user stays connected but the ircd silently
// drops their commands — a quieter alternative to an AKILL.
pub const SHUN: Xline = Xline { kind: XlineKind::Shun, name: "SHUN", target: "user@host", normalize: norm_userhost };

// CBAN: a channel-name ban. Users can't join (or create) a channel matching the
// mask, which is a channel glob like `#warez*`.
pub const CBAN: Xline = Xline { kind: XlineKind::Cban, name: "CBAN", target: "#channel", normalize: norm_channel };

fn norm_userhost(input: &str) -> Option<String> {
    let body = input.rsplit('!').next().unwrap_or(input);
    let (user, host) = body.split_once('@')?;
    if user.is_empty() || host.is_empty() || host.contains('@') {
        return None;
    }
    Some(format!("{}@{}", user.to_ascii_lowercase(), host.to_ascii_lowercase()))
}

fn norm_nick(input: &str) -> Option<String> {
    // A nick mask, not a hostmask: reject an '@' so a user typo can't become an
    // over-broad ban, and keep it non-empty.
    if input.is_empty() || input.contains('@') || input.contains('!') {
        return None;
    }
    Some(input.to_ascii_lowercase())
}

fn norm_realname(input: &str) -> Option<String> {
    // A realname regex the ircd evaluates: keep it verbatim (case matters), just
    // require it non-empty. A single token — use `.`/`\s` for spaces.
    (!input.is_empty()).then(|| input.to_string())
}

fn norm_channel(input: &str) -> Option<String> {
    // A channel-name glob: must carry a channel prefix and a non-empty body.
    if (!input.starts_with('#') && !input.starts_with('&')) || input.len() < 2 || input.contains(|c: char| c.is_whitespace() || c == ',') {
        return None;
    }
    Some(input.to_ascii_lowercase())
}

// A mask whose every meaningful character is a wildcard would match nearly all.
// A leading channel prefix is ignored so `#*` counts as too wide.
fn too_wide(mask: &str, is_regex: bool) -> bool {
    let body = mask.strip_prefix('#').or_else(|| mask.strip_prefix('&')).unwrap_or(mask);
    // A realname REGEX that's a bare quantifier over any-char (.+ / .* / .) matches
    // everyone, so treat '+' as a wildcard too — otherwise `SNLINE ADD .+` bans the
    // whole network (glob '*'/'?' and '.' are already caught).
    body.is_empty() || body.chars().all(|c| c == '*' || c == '?' || c == '.' || c == '@' || (is_regex && c == '+'))
}

fn human_secs(secs: u64) -> String {
    match secs {
        0 => "moments".to_string(),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86_400 => format!("{}h", s / 3600),
        s => format!("{}d", s / 86_400),
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
