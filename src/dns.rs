//! A minimal native DNS resolver — just enough to look up MX and A/AAAA records
//! for the registration MX-blacklist. Deliberately tiny and dependency-free (echo
//! keeps its dependency set small): it builds a DNS query, sends it over UDP to a
//! configured recursive resolver, and parses the answer *defensively* — every read
//! is bounds-checked, and name-compression pointer chains are capped, so a hostile
//! or truncated response can never loop or panic, only yield fewer records.

use rand_core::{OsRng, RngCore};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::net::UdpSocket;

const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;
const QTYPE_MX: u16 = 15;
const CLASS_IN: u16 = 1;

// An MX record: (preference, exchange hostname). Lower preference is preferred.
struct Mx {
    preference: u16,
    exchange: String,
}

// The recursive resolver to query: the first `nameserver` in /etc/resolv.conf, or
// systemd-resolved's stub as a fallback. `override_addr` (from config) wins if set.
pub fn resolver_addr(override_addr: &str) -> String {
    if !override_addr.is_empty() {
        return with_port(override_addr);
    }
    if let Ok(conf) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in conf.lines() {
            let line = line.trim();
            if let Some(ns) = line.strip_prefix("nameserver ") {
                let ns = ns.trim();
                if !ns.is_empty() {
                    return with_port(ns);
                }
            }
        }
    }
    "127.0.0.53:53".to_string()
}

fn with_port(addr: &str) -> String {
    if addr.contains(':') && !addr.contains('.') && !addr.ends_with(']') {
        // bare IPv6 without a port — bracket it
        format!("[{addr}]:53")
    } else if addr.contains(':') {
        addr.to_string() // assume it already carries a port (or is bracketed v6)
    } else {
        format!("{addr}:53")
    }
}

// Build a DNS query packet for `name`/`qtype` with transaction id `id`.
fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(name.len() + 18);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: recursion desired
    q.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    q.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // ancount / nscount / arcount
    for label in name.split('.').filter(|l| !l.is_empty()) {
        let bytes = label.as_bytes();
        let n = bytes.len().min(63);
        q.push(n as u8);
        q.extend_from_slice(&bytes[..n]);
    }
    q.push(0); // root label
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&CLASS_IN.to_be_bytes());
    q
}

// Read a (possibly compressed) DNS name starting at `pos`. Returns the dotted name
// and the offset in the RR stream just past the name (past the first pointer, if
// compression was used). Bounded to `MAX_JUMPS` pointer hops.
fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    const MAX_JUMPS: usize = 16;
    let mut name = String::new();
    let mut jumps = 0usize;
    let mut end_after: Option<usize> = None;
    loop {
        let len = *msg.get(pos)?;
        if len & 0xC0 == 0xC0 {
            let b2 = *msg.get(pos + 1)? as usize;
            let target = (((len & 0x3F) as usize) << 8) | b2;
            if end_after.is_none() {
                end_after = Some(pos + 2);
            }
            jumps += 1;
            if jumps > MAX_JUMPS {
                return None;
            }
            pos = target;
            continue;
        }
        if len == 0 {
            pos += 1;
            break;
        }
        let len = len as usize;
        let label = msg.get(pos + 1..pos + 1 + len)?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(label));
        pos += 1 + len;
    }
    Some((name, end_after.unwrap_or(pos)))
}

fn skip_name(msg: &[u8], pos: usize) -> Option<usize> {
    read_name(msg, pos).map(|(_, end)| end)
}

// Walk the answer section, returning the (rdata_start, rdlen) of each RR whose type
// is `want`. Questions are skipped; malformed tails simply end the walk.
fn answer_rdatas(msg: &[u8], want: u16) -> Vec<(usize, usize)> {
    if msg.len() < 12 {
        return Vec::new();
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut pos = 12;
    for _ in 0..qd {
        pos = match skip_name(msg, pos) {
            Some(p) => p + 4, // qtype + qclass
            None => return Vec::new(),
        };
    }
    let mut out = Vec::new();
    for _ in 0..an {
        pos = match skip_name(msg, pos) {
            Some(p) => p,
            None => break,
        };
        if pos + 10 > msg.len() {
            break;
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        let rdata = pos + 10;
        if rdata + rdlen > msg.len() {
            break;
        }
        if rtype == want {
            out.push((rdata, rdlen));
        }
        pos = rdata + rdlen;
    }
    out
}

fn parse_mx(msg: &[u8]) -> Vec<Mx> {
    let mut out = Vec::new();
    for (start, rdlen) in answer_rdatas(msg, QTYPE_MX) {
        if rdlen < 3 {
            continue;
        }
        let preference = u16::from_be_bytes([msg[start], msg[start + 1]]);
        if let Some((exchange, _)) = read_name(msg, start + 2) {
            if !exchange.is_empty() {
                out.push(Mx { preference, exchange });
            }
        }
    }
    out
}

fn parse_a(msg: &[u8]) -> Vec<IpAddr> {
    answer_rdatas(msg, QTYPE_A)
        .into_iter()
        .filter(|&(_, l)| l == 4)
        .map(|(s, _)| IpAddr::V4(Ipv4Addr::new(msg[s], msg[s + 1], msg[s + 2], msg[s + 3])))
        .collect()
}

fn parse_aaaa(msg: &[u8]) -> Vec<IpAddr> {
    answer_rdatas(msg, QTYPE_AAAA)
        .into_iter()
        .filter(|&(_, l)| l == 16)
        .map(|(s, _)| {
            let mut o = [0u8; 16];
            o.copy_from_slice(&msg[s..s + 16]);
            IpAddr::V6(Ipv6Addr::from(o))
        })
        .collect()
}

// Send one query and return the validated response bytes (txid must match).
async fn query(resolver: &str, name: &str, qtype: u16, timeout: Duration) -> Option<Vec<u8>> {
    let id = (OsRng.next_u32() & 0xFFFF) as u16;
    let packet = build_query(id, name, qtype);
    let bind = if resolver.starts_with('[') { "[::]:0" } else { "0.0.0.0:0" };
    let sock = UdpSocket::bind(bind).await.ok()?;
    sock.connect(resolver).await.ok()?;
    sock.send(&packet).await.ok()?;
    let mut buf = vec![0u8; 1500];
    let n = tokio::time::timeout(timeout, sock.recv(&mut buf)).await.ok()?.ok()?;
    buf.truncate(n);
    if buf.len() < 12 || u16::from_be_bytes([buf[0], buf[1]]) != id {
        return None;
    }
    Some(buf)
}

/// The MX exchange hostnames for `domain`, preference-sorted. Per RFC 5321, a
/// domain with no MX falls back to its own A/AAAA (implicit MX), so an empty MX set
/// still yields the domain itself as a mail target.
pub async fn mx_hosts(resolver: &str, domain: &str, timeout: Duration) -> Vec<String> {
    let mut mxs = match query(resolver, domain, QTYPE_MX, timeout).await {
        Some(resp) => parse_mx(&resp),
        None => Vec::new(),
    };
    mxs.sort_by_key(|m| m.preference);
    if mxs.is_empty() {
        vec![domain.to_string()]
    } else {
        mxs.into_iter().map(|m| m.exchange).collect()
    }
}

/// The A + AAAA addresses for `host`.
pub async fn host_ips(resolver: &str, host: &str, timeout: Duration) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    if let Some(r) = query(resolver, host, QTYPE_A, timeout).await {
        ips.extend(parse_a(&r));
    }
    if let Some(r) = query(resolver, host, QTYPE_AAAA, timeout).await {
        ips.extend(parse_aaaa(&r));
    }
    ips
}

#[cfg(test)]
mod tests {
    use super::*;

    // Assemble a minimal DNS response: one question + the given answer RRs.
    fn response(qname: &str, answers: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&0x1234u16.to_be_bytes()); // id
        m.extend_from_slice(&0x8180u16.to_be_bytes()); // flags: response, RD, RA
        m.extend_from_slice(&1u16.to_be_bytes()); // qd
        m.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // an
        m.extend_from_slice(&[0, 0, 0, 0]); // ns/ar
        let qstart = m.len();
        for label in qname.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&QTYPE_MX.to_be_bytes());
        m.extend_from_slice(&CLASS_IN.to_be_bytes());
        for (rtype, rdata) in answers {
            // owner name: a compression pointer back to the question name
            m.extend_from_slice(&(0xC000u16 | qstart as u16).to_be_bytes());
            m.extend_from_slice(&rtype.to_be_bytes());
            m.extend_from_slice(&CLASS_IN.to_be_bytes());
            m.extend_from_slice(&300u32.to_be_bytes()); // ttl
            m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            m.extend_from_slice(rdata);
        }
        m
    }

    // MX rdata: 2-byte preference + a name (here uncompressed).
    fn mx_rdata(pref: u16, exchange: &str) -> Vec<u8> {
        let mut r = pref.to_be_bytes().to_vec();
        for label in exchange.split('.') {
            r.push(label.len() as u8);
            r.extend_from_slice(label.as_bytes());
        }
        r.push(0);
        r
    }

    #[test]
    fn parses_mx_records_preference_sorted() {
        let msg = response("example.com", &[(QTYPE_MX, mx_rdata(20, "mx2.mail.example")), (QTYPE_MX, mx_rdata(10, "mx1.mail.example"))]);
        let mut mx = parse_mx(&msg);
        mx.sort_by_key(|m| m.preference);
        assert_eq!(mx.len(), 2);
        assert_eq!(mx[0].preference, 10);
        assert_eq!(mx[0].exchange, "mx1.mail.example");
        assert_eq!(mx[1].exchange, "mx2.mail.example");
    }

    #[test]
    fn parses_a_records() {
        let msg = response("host.example", &[(QTYPE_A, vec![203, 0, 113, 7]), (QTYPE_A, vec![203, 0, 113, 8])]);
        let ips = parse_a(&msg);
        assert_eq!(ips, vec!["203.0.113.7".parse::<IpAddr>().unwrap(), "203.0.113.8".parse().unwrap()]);
    }

    #[test]
    fn compression_pointer_loop_does_not_hang() {
        // A name whose pointer points at itself must terminate (None), not loop.
        let mut msg = vec![0u8; 12];
        msg.extend_from_slice(&[0xC0, 12]); // pointer at offset 12 -> offset 12 (self)
        assert!(read_name(&msg, 12).is_none());
    }

    #[test]
    fn truncated_response_yields_nothing_no_panic() {
        let full = response("example.com", &[(QTYPE_MX, mx_rdata(10, "mx.example"))]);
        for cut in 0..full.len() {
            let _ = parse_mx(&full[..cut]); // must never panic
        }
    }

    #[tokio::test]
    #[ignore] // hits real DNS; run with `cargo test -- --ignored`
    async fn live_mx_and_a_lookup() {
        let r = resolver_addr("");
        let hosts = mx_hosts(&r, "gmail.com", Duration::from_secs(3)).await;
        assert!(!hosts.is_empty(), "gmail.com should have MX records");
        assert!(hosts.iter().any(|h| h.contains("google")), "MX hosts: {hosts:?}");
        let ips = host_ips(&r, &hosts[0], Duration::from_secs(3)).await;
        assert!(!ips.is_empty(), "MX host {} should resolve to IPs", hosts[0]);
        eprintln!("resolver={r}  gmail.com MX={hosts:?}  {} -> {ips:?}", hosts[0]);
    }

    #[test]
    fn query_roundtrips_id_and_qname_bytes() {
        let q = build_query(0xABCD, "mail.example.com", QTYPE_MX);
        assert_eq!(u16::from_be_bytes([q[0], q[1]]), 0xABCD);
        assert_eq!(u16::from_be_bytes([q[2], q[3]]), 0x0100); // RD
        // qname labels present
        assert!(q.windows(4).any(|w| w == b"mail"));
    }
}
