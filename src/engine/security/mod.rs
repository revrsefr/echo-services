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
        if !self.security.on() {
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
        // makes arming possible (loopback is exempt by default).
        if self.security.is_exempt(&ip) {
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
        let verb = if armed { "\x02acting on\x02" } else { "would act on (report-only)" };
        if let Some(line) = self.feed("SECURITY", format!("{kind}: {verb} \x02{who}\x02 · {why}")) {
            out.push(line);
        }
        if armed && !self.sid.is_empty() {
            let reason = format!("Security: {kind} ({why})");
            out.push(NetAction::KillUser { from: self.sid.clone(), uid: uid.to_string(), reason: reason.clone() });
            if ban_secs > 0 {
                let expires = self.now_secs() + ban_secs;
                let _ = self.db.akill_add(echo_api::XlineKind::Gline, mask, "Security", &reason, Some(expires));
                out.push(NetAction::AddLine {
                    kind: "G".to_string(),
                    mask: mask.to_string(),
                    setter: "Security".to_string(),
                    duration: ban_secs,
                    reason,
                });
            }
        }
        out
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
        let sec = Security { cfg: None, counters: Counters::default(), patterns: compiled };
        assert!(sec.match_pattern("evil", "x", "node.spamhost", "g").is_some()); // glob on mask
        assert!(sec.match_pattern("BOT42", "x", "clean.host", "g").is_some()); // case-insensitive regex on nick
        assert!(sec.match_pattern("alice", "x", "clean.host", "hello").is_none());
    }
}
