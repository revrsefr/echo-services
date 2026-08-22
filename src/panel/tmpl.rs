//! Static asset embedding for the web panel (CSS/JS). The pages themselves are
//! compile-time askama templates (see `src/panel/site/templates`, rendered by the
//! typed structs in `mod.rs`); this module only serves the theme's static files.

use include_dir::{include_dir, Dir};

static STATIC: Dir = include_dir!("$CARGO_MANIFEST_DIR/src/panel/site/static");

/// A static asset (css/js/…) by its path under `static/`, e.g. `css/theme.css`.
pub fn asset(path: &str) -> Option<(&'static [u8], &'static str)> {
    let f = STATIC.get_file(path)?;
    let ctype = match path.rsplit('.').next() {
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    };
    Some((f.contents(), ctype))
}

/// Percent-encode a string for use as a single URL path segment (RFC 3986
/// unreserved set kept verbatim, everything else encoded). Lets channel names
/// like `#devs` or `##dev` and nicks with reserved chars appear in a link
/// without the `#` being swallowed as a fragment.
pub fn url_seg(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// A relative timestamp in French ("il y a 3 min"), for panel display. Computed in
/// Rust so templates stay pure interpolation.
pub fn human_ago(then: u64, now: u64) -> String {
    let s = now.saturating_sub(then);
    if s < 60 {
        "à l'instant".into()
    } else if s < 3600 {
        format!("il y a {} min", s / 60)
    } else if s < 86400 {
        format!("il y a {} h", s / 3600)
    } else if s < 2_592_000 {
        format!("il y a {} j", s / 86400)
    } else {
        format!("il y a {} mois", s / 2_592_000)
    }
}

/// Format a unix timestamp as "dd/mm HH:MM" (UTC). Self-contained civil-date
/// conversion so templates can show absolute times without a date crate.
pub fn fmt_dt(ts: u64) -> String {
    if ts == 0 {
        return "—".into();
    }
    let days = (ts / 86400) as i64;
    let secs = ts % 86400;
    let (h, mi) = (secs / 3600, (secs % 3600) / 60);
    // days since 1970-01-01 → civil (y, m, d), Howard Hinnant's algorithm.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let _ = y;
    format!("{:02}/{:02} {:02}:{:02}", d, m, h, mi)
}

/// Format a unix timestamp as "dd/mm/yyyy HH:MM" (UTC).
pub fn fmt_date(ts: u64) -> String {
    if ts == 0 {
        return "—".into();
    }
    let days = (ts / 86400) as i64;
    let secs = ts % 86400;
    let (h, mi) = (secs / 3600, (secs % 3600) / 60);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{:02}/{:02}/{} {:02}:{:02}", d, m, y, h, mi)
}

/// A forward relative delay in French ("dans 3 j"), for expiry display.
pub fn human_until(now: u64, then: u64) -> String {
    let s = then.saturating_sub(now);
    if s < 60 {
        "dans moins d'une minute".into()
    } else if s < 3600 {
        format!("dans {} min", s / 60)
    } else if s < 86400 {
        format!("dans {} h", s / 3600)
    } else if s < 2_592_000 {
        format!("dans {} j", s / 86400)
    } else {
        format!("dans {} mois", s / 2_592_000)
    }
}
