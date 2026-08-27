//! The registration MX-blacklist policy.
//!
//! Resolves an email domain's mail servers (MX records, then their A/AAAA) and
//! blocks the registration when any mail-server hostname matches a configured glob
//! or its IP falls in a configured CIDR. This is the stable way to stop disposable-
//! email signup abuse: spammers rotate through endless throwaway domains, but those
//! domains route mail through a small, slow-changing set of mail servers — so one
//! `mx_globs`/`ip_cidrs` entry catches every domain behind that infrastructure,
//! including brand-new ones.
//!
//! Runs from the link layer (async, off the engine lock) between the cheap
//! pre-register gate and account creation, using the native [`crate::dns`] resolver.

use crate::config::MxBlocklist;
use crate::dns;
use std::net::IpAddr;
use std::time::Duration;

/// `Some(reason)` when `email`'s mail infrastructure is blocklisted, else `None`.
pub async fn check(cfg: &MxBlocklist, email: &str) -> Option<String> {
    if cfg.mx_globs.is_empty() && cfg.ip_cidrs.is_empty() {
        return None; // nothing configured to match against
    }
    let domain = email.rsplit_once('@')?.1.trim().to_ascii_lowercase();
    if domain.is_empty() {
        return None;
    }
    let resolver = dns::resolver_addr(&cfg.resolver);
    let timeout = Duration::from_millis(cfg.timeout_ms.max(200));
    for host in dns::mx_hosts(&resolver, &domain, timeout).await {
        let host = host.to_ascii_lowercase();
        if cfg.mx_globs.iter().any(|g| crate::engine::db::glob_match(g, &host)) {
            return Some(format!("mail server {host} is blocklisted"));
        }
        if !cfg.ip_cidrs.is_empty() {
            for ip in dns::host_ips(&resolver, &host, timeout).await {
                if cfg.ip_cidrs.iter().any(|c| ip_in_cidr(ip, c)) {
                    return Some(format!("mail server {host} ({ip}) is in a blocklisted range"));
                }
            }
        }
    }
    None
}

// Whether `ip` falls within `cidr` — a bare address matches exactly, else the
// network of an "a.b.c.0/24" / "2001:db8::/32". Malformed/cross-family never match.
fn ip_in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let (net_s, prefix_s) = cidr.split_once('/').unwrap_or((cidr, ""));
    let Ok(net) = net_s.parse::<IpAddr>() else {
        return false;
    };
    match (ip, net) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            let p = prefix_s.parse::<u8>().unwrap_or(32).min(32);
            let m = if p == 0 { 0 } else { u32::MAX << (32 - p) };
            (u32::from(ip) & m) == (u32::from(net) & m)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            let p = prefix_s.parse::<u8>().unwrap_or(128).min(128);
            let m = if p == 0 { 0 } else { u128::MAX << (128 - p) };
            (u128::from(ip) & m) == (u128::from(net) & m)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::ip_in_cidr;

    #[test]
    fn cidr_membership() {
        assert!(ip_in_cidr("203.0.113.9".parse().unwrap(), "203.0.113.0/24"));
        assert!(!ip_in_cidr("203.0.114.9".parse().unwrap(), "203.0.113.0/24"));
        assert!(ip_in_cidr("203.0.113.9".parse().unwrap(), "203.0.113.9"));
        assert!(ip_in_cidr("2001:db8::1".parse().unwrap(), "2001:db8::/32"));
        assert!(!ip_in_cidr("203.0.113.9".parse().unwrap(), "2001:db8::/32"));
    }
}
