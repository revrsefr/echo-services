//! Native anti-abuse subsystem, integrated into the engine core — deliberately
//! NOT a service pseudo-client. It watches the connect/quit/nick/join/message
//! events the engine already processes and reports (or, when armed, enforces) per
//! the `[security]` config.
//!
//! The detection algorithms are modelled on Sigyn/ozone (the anti-abuse bot that
//! guarded freenode/Libera), but because echo is linked as a pseudo-server it
//! receives those events first-class over S2S and issues bans server-side — so
//! all of that bot's oper-login, snote-scraping and IP-resolution plumbing is
//! unnecessary here. Only the heuristics carry over.
//!
//! Enforcement is gated: `enabled=false` (the default) makes the whole subsystem
//! inert; `report_only=true` (also the default when enabled) announces detections
//! to the staff log channel without killing or banning, so thresholds can be
//! trusted before the engine is armed.

mod counter;

use counter::Counters;
use crate::config;
use crate::proto::NetAction;
use regex::Regex;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;

#[derive(Default)]
pub(crate) struct Security {
    // The live tunables. None (or `enabled=false`) means the subsystem is inert.
    cfg: Option<config::Security>,
    // Ephemeral per-key rate windows, kept across a rehash.
    counters: Counters,
    // Operator connection-pattern matchers, compiled from `cfg.pattern` on every
    // (re)configure. Empty when none are set.
    patterns: Vec<CompiledPattern>,
    // Detectors are suppressed until this unix time — set after a server split/link so
    // a netsplit rejoin doesn't trip them. 0 = not in a suppression window.
    quiet_until: u64,
    // Accounts recently banned by the subsystem, mapped to when to forget them; a
    // re-login is re-enforced until then (ban evasion). Not the counter engine because
    // its multi-day window far outlives the counters' 1-hour GC.
    evaded: HashMap<String, u64>,
}

impl Security {
    // (Re)apply config. The counters deliberately survive a rehash — only the
    // thresholds change, not the in-flight rate state — but the pattern matchers are
    // recompiled from the new config.
    pub fn configure(&mut self, cfg: Option<config::Security>) {
        self.patterns = cfg.as_ref().map(|c| compile_patterns(&c.pattern)).unwrap_or_default();
        self.cfg = cfg;
    }

    // Master switch: the subsystem runs at all.
    fn on(&self) -> bool {
        self.cfg.as_ref().is_some_and(|c| c.enabled)
    }

    // Armed: run detectors AND enforce (kill/ban), rather than only reporting.
    fn enforcing(&self) -> bool {
        self.cfg.as_ref().is_some_and(|c| c.enabled && !c.report_only)
    }

    // Enter a post-split quiet period so a netsplit rejoin doesn't storm the detectors.
    pub(crate) fn mark_netsplit(&mut self, now: u64) {
        if let Some(grace) = self.cfg.as_ref().map(|c| c.netsplit_grace) {
            self.quiet_until = self.quiet_until.max(now.saturating_add(grace));
        }
    }
    fn in_netsplit(&self, now: u64) -> bool {
        now < self.quiet_until
    }

    // Remember a just-banned account (ban evasion), pruning expired entries as we go.
    fn remember_ban(&mut self, account: String, now: u64, ttl: u64) {
        self.evaded.retain(|_, exp| *exp > now);
        self.evaded.insert(account, now.saturating_add(ttl));
    }
    fn is_evader(&self, account: &str, now: u64) -> bool {
        self.evaded.get(account).is_some_and(|&exp| now < exp)
    }

    // Trusted infrastructure that must never be screened or banned (loopback, the
    // services host, gateways). This is the valve that makes arming safe — without
    // it an armed connection-flood from localhost would G-line 127.0.0.1 and cut off
    // the local bots and the services link. Defaults to loopback.
    fn is_exempt(&self, ip: &str) -> bool {
        self.cfg.as_ref().is_some_and(|c| c.exempt_ips.iter().any(|e| ip_in_cidr(ip, e)))
    }

    // The first operator pattern that matches this connection's identity, as
    // (reason, ban_seconds). None when no pattern is configured or matches.
    fn match_pattern(&self, nick: &str, ident: &str, host: &str, gecos: &str) -> Option<(String, u64)> {
        if self.patterns.is_empty() {
            return None;
        }
        let mask = format!("{nick}!{ident}@{host}");
        let full = format!("{mask}#{gecos}");
        for p in &self.patterns {
            let target = match p.field {
                PatField::Mask => mask.as_str(),
                PatField::Full => full.as_str(),
                PatField::Nick => nick,
                PatField::Ident => ident,
                PatField::Host => host,
                PatField::Gecos => gecos,
            };
            let hit = match &p.matcher {
                Matcher::Glob(g) => crate::engine::db::glob_match(g, target),
                Matcher::Regex(re) => re.is_match(target),
            };
            if hit {
                return Some((p.reason.clone(), p.ban));
            }
        }
        None
    }
}

// Which part of a connecting user's identity a pattern tests.
enum PatField {
    Mask, // nick!ident@host (default)
    Full, // nick!ident@host#gecos
    Nick,
    Ident,
    Host,
    Gecos,
}

impl PatField {
    fn parse(s: &str) -> PatField {
        match s.to_ascii_lowercase().as_str() {
            "full" => PatField::Full,
            "nick" => PatField::Nick,
            "ident" | "user" => PatField::Ident,
            "host" => PatField::Host,
            "gecos" | "realname" => PatField::Gecos,
            _ => PatField::Mask,
        }
    }
}

enum Matcher {
    Glob(String),
    Regex(Regex),
}

struct CompiledPattern {
    field: PatField,
    matcher: Matcher,
    reason: String,
    ban: u64,
}

// Compile operator pattern definitions, skipping (with a warning) any regex that
// won't compile so one bad pattern can't sink the rest.
fn compile_patterns(defs: &[config::Pattern]) -> Vec<CompiledPattern> {
    let mut out = Vec::new();
    for p in defs {
        let matcher = if p.regex {
            match regex::RegexBuilder::new(&p.mask).case_insensitive(true).size_limit(1 << 20).build() {
                Ok(re) => Matcher::Regex(re),
                Err(e) => {
                    tracing::warn!(pattern = %p.mask, error = %e, "security: ignoring un-compilable regex pattern");
                    continue;
                }
            }
        } else {
            Matcher::Glob(p.mask.clone())
        };
        out.push(CompiledPattern { field: PatField::parse(&p.field), matcher, reason: p.reason.clone(), ban: p.ban });
    }
    out
}

// True when `ip` falls within `cidr` — a bare address (no `/`) matches exactly, a
// "a.b.c.0/24" / "2001:db8::/32" matches the network. Malformed or cross-family
// inputs are never a match.
fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    let (net_s, prefix_s) = cidr.split_once('/').unwrap_or((cidr, ""));
    let (ip, net): (IpAddr, IpAddr) = match (ip.parse(), net_s.parse()) {
        (Ok(a), Ok(b)) => (a, b),
        _ => return false,
    };
    match (ip, net) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            let prefix = prefix_s.parse::<u8>().unwrap_or(32).min(32);
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            (u32::from(ip) & mask) == (u32::from(net) & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            let prefix = prefix_s.parse::<u8>().unwrap_or(128).min(128);
            let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
            (u128::from(ip) & mask) == (u128::from(net) & mask)
        }
        _ => false,
    }
}

// A quit reason is a "broken client" signal when it contains any configured marker
// (case-insensitive substring), e.g. "Excess Flood" / "Max SendQ exceeded".
fn quit_matches(reason: &str, markers: &[String]) -> bool {
    let r = reason.to_ascii_lowercase();
    markers.iter().any(|m| !m.is_empty() && r.contains(&m.to_ascii_lowercase()))
}

// How many distinct member nicks (already lowercased + length-filtered) `text`
// mentions as whole words — the mass-ping / highlight-spam signal. Tokenises on
// non-nick characters so a nick that is merely a substring of a word doesn't count.
fn count_highlights(text: &str, member_nicks_lc: &std::collections::HashSet<String>) -> usize {
    if member_nicks_lc.is_empty() {
        return 0;
    }
    let mut hit = std::collections::HashSet::new();
    for tok in text.split(|c: char| !(c.is_alphanumeric() || "[]{}\\`|^_-".contains(c))) {
        if tok.is_empty() {
            continue;
        }
        let low = tok.to_ascii_lowercase();
        if member_nicks_lc.contains(&low) {
            hit.insert(low);
        }
    }
    hit.len()
}

// A crude "bad unicode" fraction in [0,1]: the share of characters that are
// combining marks (zalgo) or invisible/zero-width formatting (injection). IRC
// formatting codes are ignored, and precomposed accents aren't combining marks, so
// ordinary and accented text score ~0. No Unicode database needed.
fn bad_unicode_score(text: &str) -> f64 {
    let mut total = 0usize;
    let mut bad = 0usize;
    for c in text.chars() {
        let u = c as u32;
        // IRC formatting (bold/colour/italic/…) is legitimate — don't count it.
        if matches!(u, 0x02 | 0x03 | 0x04 | 0x0F | 0x11 | 0x16 | 0x1D | 0x1E | 0x1F) {
            continue;
        }
        total += 1;
        let combining = matches!(u,
            0x0300..=0x036F | 0x0483..=0x0489 | 0x1AB0..=0x1AFF | 0x1DC0..=0x1DFF | 0x20D0..=0x20FF | 0xFE20..=0xFE2F);
        let invisible = matches!(u,
            0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0xFEFF | 0x00AD | 0x180E | 0x3164 | 0xFFA0);
        if combining || invisible {
            bad += 1;
        }
    }
    if total == 0 {
        0.0
    } else {
        bad as f64 / total as f64
    }
}

// The coarse aggregation key for an address — the /24 for IPv4, the /64 for IPv6
// — used to catch clone floods spread across a subnet.
fn cidr_of(ip: &str) -> String {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            let o = v4.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
        Err(_) => ip.to_string(),
    }
}

impl super::Engine {
    // Screen a just-connected user. Called from the `UserAttrs` arm, where the
    // full nick!ident@host#gecos identity is known. Returns any report/enforce
    // actions; a no-op (empty) when the subsystem is off or nothing tripped.
    pub(crate) fn security_screen_connect(&mut self, uid: &str) -> Vec<NetAction> {
        if !self.security.on() || self.security.in_netsplit(self.now_secs()) {
            return Vec::new();
        }
        // Snapshot identity, then drop the network borrow before touching counters.
        let (ip, nick, ident, host, gecos) = match self.network.ban_target(uid) {
            Some(bt) => (
                bt.ip.to_string(),
                bt.nick.to_string(),
                bt.ident.to_string(),
                bt.host.to_string(),
                bt.gecos.to_string(),
            ),
            None => return Vec::new(),
        };
        if ip.is_empty() {
            return Vec::new();
        }
        // Trusted infrastructure is never screened or banned — the safety valve that
        // makes arming possible (loopback is exempt by default), and neither are
        // trusted identities (operators, and optionally accounts).
        if self.security.is_exempt(&ip) || self.trusted_identity(uid, None) {
            return Vec::new();
        }
        let who = format!("{nick}!{ident}@{host}");
        // 1) Operator pattern DB: a matching nick!ident@host(#gecos) is acted on at once.
        if let Some((reason, ban)) = self.security.match_pattern(&nick, &ident, &host, &gecos) {
            self.bump("security.pattern.hits");
            return self.security_act(&who, uid, &format!("*@{ip}"), "connection pattern", &reason, ban);
        }
        // 2) Per-IP and per-range connection-flood windows.
        let Some(rules) = self.security.cfg.as_ref().map(|c| c.connect.clone()) else {
            return Vec::new();
        };
        if !rules.enabled {
            return Vec::new();
        }
        let now = self.now_secs();
        let n_ip = self.security.counters.hit(&format!("cf|{ip}"), now, rules.flood_life);
        let range = cidr_of(&ip);
        let n_range = self.security.counters.hit(&format!("cr|{range}"), now, rules.range_life);
        // A single IP over its permit bans that IP; a subnet over its permit bans
        // the whole range (the clone-flood signal).
        let trip = if n_ip > rules.flood_permit {
            Some((format!("*@{ip}"), format!("{n_ip} connections in {}s from {ip}", rules.flood_life)))
        } else if n_range > rules.range_permit {
            Some((format!("*@{range}"), format!("{n_range} connections in {}s from range {range}", rules.range_life)))
        } else {
            None
        };
        let Some((mask, why)) = trip else {
            return Vec::new();
        };
        self.bump("security.connect.trips");
        self.security_act(&who, uid, &mask, "connection flood", &why, rules.ban_duration)
    }

    // Common report-or-enforce path. Always announces to the staff log channel;
    // only kills the user and lays a network ban when the subsystem is armed
    // (enabled && !report_only).
    fn security_act(&mut self, who: &str, uid: &str, mask: &str, kind: &str, why: &str, ban_secs: u64) -> Vec<NetAction> {
        let mut out = Vec::new();
        let armed = self.security.enforcing();
        let now = self.now_secs();
        let (ann_permit, ann_life, casc_permit, casc_life) = self
            .security
            .cfg
            .as_ref()
            .map(|c| (c.announce_permit, c.announce_life, c.cascade_permit, c.cascade_life))
            .unwrap_or((0, 1, u32::MAX, 1));
        // Rate-limit staff-feed announcements so a sustained flood can't spam the log
        // channel; enforcement below still runs on every trigger.
        let shown = self.security.counters.hit("sec|announce", now, ann_life);
        let verb = if armed { "\x02acting on\x02" } else { "would act on (report-only)" };
        if shown <= ann_permit {
            if let Some(line) = self.feed("SECURITY", format!("{kind}: {verb} \x02{who}\x02 · {why}")) {
                out.push(line);
            }
        } else if shown == ann_permit + 1 {
            if let Some(line) = self.feed("SECURITY", format!("further \x02SECURITY\x02 alerts muted for {ann_life}s (over {ann_permit} in the window)")) {
                out.push(line);
            }
        }
        // Abuse-cascade signal: many triggers network-wide in the window → recommend
        // DEFCON, once as it crosses the threshold.
        let trips = self.security.counters.hit("sec|cascade", now, casc_life);
        if trips == casc_permit.saturating_add(1) {
            if let Some(line) = self.feed("SECURITY", format!("\x02ABUSE CASCADE\x02: {trips} triggers in {casc_life}s — consider raising DEFCON")) {
                out.push(line);
            }
        }
        if armed && !self.sid.is_empty() {
            let reason = format!("Security: {kind} ({why})");
            out.push(NetAction::KillUser { from: self.sid.clone(), uid: uid.to_string(), reason: reason.clone() });
            if ban_secs > 0 {
                let expires = now + ban_secs;
                let _ = self.db.akill_add(echo_api::XlineKind::Gline, mask, "Security", &reason, Some(expires));
                out.push(NetAction::AddLine {
                    kind: "G".to_string(),
                    mask: mask.to_string(),
                    setter: "Security".to_string(),
                    duration: ban_secs,
                    reason,
                });
            }
            // Ban evasion: remember a logged-in offender's account so a later re-login
            // from a new nick/IP is re-enforced (security_screen_login).
            if let (Some(ttl), Some(account)) =
                (self.security.cfg.as_ref().map(|c| c.auth.evade_ttl), self.network.account_of(uid).map(str::to_string))
            {
                self.security.remember_ban(account, now, ttl);
            }
        }
        out
    }

    // The behavioural rules, if the subsystem and the behaviour detectors are on.
    fn behavior_rules(&self) -> Option<config::BehaviorRules> {
        let c = self.security.cfg.as_ref()?;
        (c.enabled && c.behavior.enabled).then(|| c.behavior.clone())
    }

    // Beyond the IP exemption: network operators (staff) are always trusted
    // (config-gated), logged-in accounts optionally, and — with a channel — voiced
    // or opped members for content checks.
    fn trusted_identity(&self, uid: &str, channel: Option<&str>) -> bool {
        let Some(c) = self.security.cfg.as_ref() else {
            return false;
        };
        if c.exempt_opers && self.network.is_oper(uid) {
            return true;
        }
        if c.exempt_accounts && self.network.account_of(uid).is_some() {
            return true;
        }
        if let (true, Some(ch)) = (c.exempt_voice, channel) {
            if self.network.is_op(ch, uid) || self.network.is_voiced(ch, uid) {
                return true;
            }
        }
        false
    }

    // (ip, nick!ident@host) for a uid, or None when it can't be resolved, its IP is
    // exempt, or its identity is trusted — the shared gate for the behavioural and
    // content detectors. `channel` enables the voiced/opped exemption for content.
    fn security_identity(&self, uid: &str, channel: Option<&str>) -> Option<(String, String)> {
        if self.security.in_netsplit(self.now_secs()) {
            return None;
        }
        let (ip, who) = self.network.abuse_ident(uid)?;
        if ip.is_empty() || self.security.is_exempt(&ip) || self.trusted_identity(uid, channel) {
            return None;
        }
        Some((ip, who))
    }

    // Nick-change flood.
    pub(crate) fn security_screen_nick(&mut self, uid: &str) -> Vec<NetAction> {
        let Some(rules) = self.behavior_rules() else {
            return Vec::new();
        };
        let Some((ip, who)) = self.security_identity(uid, None) else {
            return Vec::new();
        };
        let now = self.now_secs();
        if self.security.counters.hit(&format!("nf|{uid}"), now, rules.nick_life) > rules.nick_permit {
            self.bump("security.nick.trips");
            return self.security_act(&who, uid, &format!("*@{ip}"), "nick-change flood", &format!("more than {} nick changes in {}s", rules.nick_permit, rules.nick_life), rules.ban_duration);
        }
        Vec::new()
    }

    // On join: note it briefly (for join-spam-part) and check mass-join per /24 or /64.
    pub(crate) fn security_screen_join(&mut self, uid: &str, channel: &str) -> Vec<NetAction> {
        let Some(rules) = self.behavior_rules() else {
            return Vec::new();
        };
        let Some((ip, who)) = self.security_identity(uid, None) else {
            return Vec::new();
        };
        let now = self.now_secs();
        self.security.counters.hit(&format!("jj|{uid}|{channel}"), now, rules.joinpart_grace);
        let range = cidr_of(&ip);
        let n = self.security.counters.hit(&format!("mj|{channel}|{range}"), now, rules.massjoin_life);
        if n > rules.massjoin_permit {
            self.bump("security.massjoin.trips");
            return self.security_act(&who, uid, &format!("*@{range}"), "mass-join flood", &format!("{n} joins to {channel} from range {range} in {}s", rules.massjoin_life), rules.ban_duration);
        }
        // Channel-crawl: one user joining many channels fast (a spam spider).
        if self.security.counters.hit(&format!("cw|{uid}"), now, rules.crawl_life) > rules.crawl_permit {
            self.bump("security.crawl.trips");
            return self.security_act(&who, uid, &format!("*@{ip}"), "channel crawl", &format!("joined too many channels in {}s", rules.crawl_life), rules.ban_duration);
        }
        Vec::new()
    }

    // On part: raw cycle rate, then quick join-then-part (join-spam-part).
    pub(crate) fn security_screen_part(&mut self, uid: &str, channel: &str) -> Vec<NetAction> {
        let Some(rules) = self.behavior_rules() else {
            return Vec::new();
        };
        let Some((ip, who)) = self.security_identity(uid, None) else {
            return Vec::new();
        };
        let now = self.now_secs();
        if self.security.counters.hit(&format!("cy|{uid}"), now, rules.cycle_life) > rules.cycle_permit {
            self.bump("security.cycle.trips");
            return self.security_act(&who, uid, &format!("*@{ip}"), "join/part cycle", &format!("more than {} parts in {}s", rules.cycle_permit, rules.cycle_life), rules.ban_duration);
        }
        let quick = self.security.counters.count(&format!("jj|{uid}|{channel}"), now, rules.joinpart_grace) > 0;
        if quick && self.security.counters.hit(&format!("jsp|{uid}"), now, rules.joinpart_life) > rules.joinpart_permit {
            self.bump("security.joinspampart.trips");
            return self.security_act(&who, uid, &format!("*@{ip}"), "join-spam-part", &format!("repeated quick join/part (last: {channel})"), rules.ban_duration);
        }
        Vec::new()
    }

    // On quit: broken-client quit flood — repeated flood/sendq kills from one IP.
    pub(crate) fn security_screen_quit(&mut self, uid: &str, reason: &str) -> Vec<NetAction> {
        let Some(rules) = self.behavior_rules() else {
            return Vec::new();
        };
        if !quit_matches(reason, &rules.quit_reasons) {
            return Vec::new();
        }
        let Some((ip, who)) = self.security_identity(uid, None) else {
            return Vec::new();
        };
        let now = self.now_secs();
        if self.security.counters.hit(&format!("qf|{ip}"), now, rules.quit_life) > rules.quit_permit {
            self.bump("security.quitflood.trips");
            return self.security_act(&who, uid, &format!("*@{ip}"), "broken-client quit flood", &format!("repeated \"{reason}\" from {ip}"), rules.ban_duration);
        }
        Vec::new()
    }

    // Content rules, if the subsystem and the content detectors are both on.
    fn content_rules(&self) -> Option<config::ContentRules> {
        let c = self.security.cfg.as_ref()?;
        (c.enabled && c.content.enabled).then(|| c.content.clone())
    }

    // Distinct channel members (nick at least `min_len` chars) this line pings.
    fn channel_highlights(&self, channel: &str, text: &str, min_len: usize) -> usize {
        let uids: Vec<String> = self.network.channel_members(channel).map(|u| u.to_string()).collect();
        let nicks: std::collections::HashSet<String> = uids
            .iter()
            .filter_map(|u| self.network.nick_of(u))
            .filter(|n| n.chars().count() >= min_len)
            .map(|n| n.to_ascii_lowercase())
            .collect();
        count_highlights(text, &nicks)
    }

    // Screen a channel message echo can see (a bot is present). The additive
    // heuristic the kickers lack: highlight-spam (mass-ping).
    pub(crate) fn security_screen_message(&mut self, from: &str, channel: &str, text: &str) -> Vec<NetAction> {
        let Some(rules) = self.content_rules() else {
            return Vec::new();
        };
        let Some((ip, who)) = self.security_identity(from, Some(channel)) else {
            return Vec::new();
        };
        let ban = format!("*@{ip}");
        // Highlight-spam (mass-ping).
        let n = self.channel_highlights(channel, text, rules.highlight_min_len as usize);
        if n >= rules.highlight_nicks as usize {
            let now = self.now_secs();
            if self.security.counters.hit(&format!("hl|{from}"), now, rules.highlight_life) > rules.highlight_permit {
                self.bump("security.highlight.trips");
                return self.security_act(&who, from, &ban, "highlight spam", &format!("pinged {n} users in {channel}"), rules.ban_duration);
            }
        }
        // Bad-unicode (zalgo / zero-width injection).
        if text.chars().count() >= rules.badunicode_min as usize && bad_unicode_score(text) >= rules.badunicode_score {
            let now = self.now_secs();
            if self.security.counters.hit(&format!("bu|{from}"), now, rules.badunicode_life) > rules.badunicode_permit {
                self.bump("security.badunicode.trips");
                return self.security_act(&who, from, &ban, "bad-unicode spam", &format!("zalgo/zero-width text in {channel}"), rules.ban_duration);
            }
        }
        // Repeat-wave (copy-paste spam); the offending line is surfaced as a pattern.
        let norm = text.trim().to_ascii_lowercase();
        if norm.chars().count() >= rules.repeat_min as usize {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            norm.hash(&mut h);
            let now = self.now_secs();
            if self.security.counters.hit(&format!("rp|{channel}|{:x}", h.finish()), now, rules.repeat_life) > rules.repeat_permit {
                self.bump("security.repeat.trips");
                let sample: String = norm.chars().take(50).collect();
                return self.security_act(&who, from, &ban, "repeat-spam wave", &format!("line repeated in {channel}: \"{sample}\""), rules.ban_duration);
            }
        }
        Vec::new()
    }

    // The login/registration abuse rules, if the subsystem and they are enabled.
    fn auth_rules(&self) -> Option<config::AuthRules> {
        let c = self.security.cfg.as_ref()?;
        (c.enabled && c.auth.enabled).then(|| c.auth.clone())
    }

    // A failed password login → brute-force detector, keyed by the client IP.
    pub(crate) fn security_screen_auth(&mut self, uid: &str, _account: &str) -> Vec<NetAction> {
        let Some(rules) = self.auth_rules() else {
            return Vec::new();
        };
        let Some((ip, who)) = self.security_identity(uid, None) else {
            return Vec::new();
        };
        let now = self.now_secs();
        if self.security.counters.hit(&format!("af|{ip}"), now, rules.fail_life) > rules.fail_permit {
            self.bump("security.authfail.trips");
            return self.security_act(&who, uid, &format!("*@{ip}"), "auth brute-force", &format!("repeated failed logins from {ip}"), rules.ban_duration);
        }
        Vec::new()
    }

    // A REGISTER from `uid`: Some(staff-alert actions) when its IP is over the
    // registration-flood limit (the caller then rejects the registration), else None.
    pub(crate) fn security_register_flood(&mut self, uid: &str) -> Option<Vec<NetAction>> {
        let rules = self.auth_rules()?;
        let (ip, who) = self.security_identity(uid, None)?;
        let now = self.now_secs();
        if self.security.counters.hit(&format!("rf|{ip}"), now, rules.register_life) > rules.register_permit {
            self.bump("security.regflood.trips");
            let mut out = Vec::new();
            if let Some(line) = self.feed("SECURITY", format!("registration flood: \x02{who}\x02 · too many from {ip} in {}s — rejected", rules.register_life)) {
                out.push(line);
            }
            return Some(out);
        }
        None
    }

    // A user logged into `account`: re-enforce if that account was recently
    // security-banned (ban evasion), refreshing the memory so it stays banned.
    pub(crate) fn security_screen_login(&mut self, uid: &str, account: &str) -> Vec<NetAction> {
        let now = self.now_secs();
        if !self.security.enforcing() || !self.security.is_evader(account, now) {
            return Vec::new();
        }
        let Some((ip, who)) = self.security_identity(uid, None) else {
            return Vec::new();
        };
        if let Some(ttl) = self.security.cfg.as_ref().map(|c| c.auth.evade_ttl) {
            self.security.remember_ban(account.to_string(), now, ttl);
        }
        self.bump("security.evasion.trips");
        let ban = self.security.cfg.as_ref().map(|c| c.auth.ban_duration).unwrap_or(0);
        self.security_act(&who, uid, &format!("*@{ip}"), "ban evasion", &format!("banned account {account} logged back in"), ban)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_aggregation() {
        assert_eq!(cidr_of("203.0.113.45"), "203.0.113.0/24");
        assert_eq!(cidr_of("2001:db8:abcd:1234:5678::1"), "2001:db8:abcd:1234::/64");
        assert_eq!(cidr_of("not-an-ip"), "not-an-ip");
    }

    #[test]
    fn ip_membership() {
        assert!(ip_in_cidr("127.0.0.1", "127.0.0.0/8"));
        assert!(ip_in_cidr("127.5.6.7", "127.0.0.0/8"));
        assert!(!ip_in_cidr("128.0.0.1", "127.0.0.0/8"));
        assert!(ip_in_cidr("10.1.2.3", "10.1.2.3")); // bare = exact
        assert!(!ip_in_cidr("10.1.2.4", "10.1.2.3"));
        assert!(ip_in_cidr("::1", "::1"));
        assert!(ip_in_cidr("2001:db8::5", "2001:db8::/32"));
        assert!(!ip_in_cidr("2001:db9::5", "2001:db8::/32"));
        assert!(!ip_in_cidr("127.0.0.1", "::1")); // cross-family never matches
        assert!(!ip_in_cidr("garbage", "127.0.0.0/8"));
    }

    fn pat(mask: &str, field: &str, regex: bool) -> config::Pattern {
        config::Pattern { mask: mask.into(), field: field.into(), regex, reason: "test".into(), ban: 0 }
    }

    #[test]
    fn pattern_glob_and_regex() {
        let compiled = compile_patterns(&[
            pat("*!*@*.spamhost", "mask", false),
            pat(r"^bot\d+$", "nick", true),
            pat("(unclosed", "gecos", true), // bad regex — must be skipped, not panic
        ]);
        assert_eq!(compiled.len(), 2); // the un-compilable regex was dropped
        let sec = Security { cfg: None, counters: Counters::default(), patterns: compiled, quiet_until: 0, evaded: Default::default() };
        assert!(sec.match_pattern("evil", "x", "node.spamhost", "g").is_some()); // glob on mask
        assert!(sec.match_pattern("BOT42", "x", "clean.host", "g").is_some()); // case-insensitive regex on nick
        assert!(sec.match_pattern("alice", "x", "clean.host", "hello").is_none());
    }

    #[test]
    fn quit_reason_matching() {
        let m = vec!["Excess Flood".to_string(), "Max SendQ exceeded".to_string()];
        assert!(quit_matches("Excess Flood", &m));
        assert!(quit_matches("Closing Link: nick[1.2.3.4] (Excess Flood)", &m)); // case-insensitive substring
        assert!(!quit_matches("Ping timeout: 240 seconds", &m));
        assert!(!quit_matches("Quit: brb", &m));
        assert!(!quit_matches("Excess Flood", &[])); // no markers => never
    }

    #[test]
    fn highlight_counting() {
        use std::collections::HashSet;
        let members: HashSet<String> = ["alice", "bob", "carol", "dave"].iter().map(|s| s.to_string()).collect();
        // Distinct member nicks as whole words are counted once each.
        assert_eq!(count_highlights("hey ALICE bob carol!! bob", &members), 3);
        // A nick that's only a substring of a longer word does not count.
        assert_eq!(count_highlights("aliceish bobcat", &members), 0);
        // Non-members are ignored.
        assert_eq!(count_highlights("alice eve mallory", &members), 1);
        assert_eq!(count_highlights("anything at all", &HashSet::new()), 0);
    }

    #[test]
    fn bad_unicode_scoring() {
        assert!(bad_unicode_score("hello world, how are you") < 0.01);
        assert!(bad_unicode_score("caf\u{00E9} r\u{00E9}sum\u{00E9} na\u{00EF}ve") < 0.05); // precomposed accents fine
        // Zalgo: each base char stacked with several combining diacriticals.
        let zalgo = "a\u{0300}\u{0301}\u{0302}b\u{0300}\u{0301}\u{0302}c\u{0300}\u{0301}\u{0302}";
        assert!(bad_unicode_score(zalgo) > 0.5);
        // Zero-width chars injected between letters.
        let zw = "s\u{200B}p\u{200B}a\u{200B}m\u{200B}m\u{200B}y";
        assert!(bad_unicode_score(zw) > 0.3);
        // IRC colour codes must not count as bad unicode.
        assert!(bad_unicode_score("\u{03}04,01 red on blue \u{03}") < 0.01);
    }
}
