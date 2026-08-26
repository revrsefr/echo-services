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

#[derive(Default)]
pub(crate) struct Security {
    // The live tunables. None (or `enabled=false`) means the subsystem is inert.
    cfg: Option<config::Security>,
    // Ephemeral per-key rate windows, kept across a rehash.
    counters: Counters,
}

impl Security {
    // (Re)apply config. The counters deliberately survive a rehash — only the
    // thresholds change, not the in-flight rate state.
    pub fn configure(&mut self, cfg: Option<config::Security>) {
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
        let Some(rules) = self.security.cfg.as_ref().map(|c| c.connect.clone()) else {
            return Vec::new();
        };
        if !rules.enabled {
            return Vec::new();
        }
        // Snapshot identity, then drop the network borrow before touching counters.
        let (ip, nick, ident, host) = match self.network.ban_target(uid) {
            Some(bt) => (bt.ip.to_string(), bt.nick.to_string(), bt.ident.to_string(), bt.host.to_string()),
            None => return Vec::new(),
        };
        if ip.is_empty() {
            return Vec::new();
        }
        let now = self.now_secs();
        // Per-IP and per-range connection-flood windows.
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
        let who = format!("{nick}!{ident}@{host}");
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
    use super::cidr_of;

    #[test]
    fn cidr_aggregation() {
        assert_eq!(cidr_of("203.0.113.45"), "203.0.113.0/24");
        assert_eq!(cidr_of("2001:db8:abcd:1234:5678::1"), "2001:db8:abcd:1234::/64");
        assert_eq!(cidr_of("not-an-ip"), "not-an-ip");
    }
}
