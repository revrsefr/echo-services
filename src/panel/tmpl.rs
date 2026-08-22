//! Template engine for the web panel.
//!
//! The panel's HTML is a set of Django templates (from the tChatou webpanel). Rust
//! can't run Django's engine, so we embed the templates + static assets, translate
//! the Django-specific dialect to minijinja (Jinja2) at load, and register the few
//! custom filters/tags (`url`, `static`, `trans`, `widthratio`, `flag`, `chanslug`,
//! `humanago`, …) so the same markup renders unchanged in axum.

use include_dir::{include_dir, Dir};
use minijinja::value::{Rest, Value};
use minijinja::{Environment, UndefinedBehavior};
use std::sync::OnceLock;

static TEMPLATES: Dir = include_dir!("$CARGO_MANIFEST_DIR/src/panel/site/templates");
static STATIC: Dir = include_dir!("$CARGO_MANIFEST_DIR/src/panel/site/static");

/// A static asset (css/js) by its path under `static/`, e.g. `css/theme.css`.
pub fn asset(path: &str) -> Option<(&'static [u8], &'static str)> {
    let f = STATIC.get_file(path)?;
    let ctype = match path.rsplit('.').next() {
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        _ => "application/octet-stream",
    };
    Some((f.contents(), ctype))
}

/// Render template `name` (e.g. `ircpanel/dashboard.html`) with `ctx`.
pub fn render(name: &str, ctx: Value) -> Result<String, minijinja::Error> {
    env().get_template(name)?.render(ctx)
}

fn env() -> &'static Environment<'static> {
    static ENV: OnceLock<Environment<'static>> = OnceLock::new();
    ENV.get_or_init(build_env)
}

fn build_env() -> Environment<'static> {
    let mut env = Environment::new();
    // Chainable: a missing var — and any attribute chain through it (a.b.c) — renders
    // empty instead of erroring, so pages tolerate partial context as data is wired in.
    env.set_undefined_behavior(UndefinedBehavior::Chainable);
    // Embed every template under its `ircpanel/…` name (matches `{% extends %}`).
    add_dir(&mut env, &TEMPLATES);

    // --- Django-tag shims registered as functions ---------------------------
    env.add_function("url", django_url);
    env.add_function("static_url", |p: String| format!("/static/{p}"));
    env.add_function("widthratio", |a: f64, b: f64, c: f64| -> i64 {
        if b == 0.0 { 0 } else { (a * c / b).round() as i64 }
    });

    // --- filters ------------------------------------------------------------
    // Django `default` triggers on any falsy value (empty string / none), not just
    // undefined like minijinja's built-in — override it to match.
    env.add_filter("default", |v: Value, d: Value| -> Value {
        let empty = v.is_undefined() || v.is_none() || v.as_str() == Some("");
        if empty { d } else { v }
    });
    env.add_filter("truncatechars", |s: String, n: usize| -> String {
        if s.chars().count() <= n {
            s
        } else {
            let keep = n.saturating_sub(1);
            format!("{}…", s.chars().take(keep).collect::<String>())
        }
    });
    // Django slice: ":N" / "N:" / "N:M" over a sequence.
    env.add_filter("slice", |v: Value, spec: String| -> Value {
        let items: Vec<Value> = v.try_iter().map(|it| it.collect()).unwrap_or_default();
        let len = items.len() as i64;
        let norm = |x: i64| if x < 0 { (len + x).max(0) } else { x.min(len) } as usize;
        let (a, b) = spec.split_once(':').unwrap_or((spec.as_str(), ""));
        let start = if a.is_empty() { 0 } else { norm(a.parse().unwrap_or(0)) };
        let end = if b.is_empty() { len as usize } else { norm(b.parse().unwrap_or(len)) };
        Value::from(items.get(start..end.max(start)).unwrap_or(&[]).to_vec())
    });
    // Tolerate a not-yet-provided list var: |length of undefined/none is 0 (the
    // built-in errors), so a page renders with empty sections before its data lands.
    env.add_filter("length", |v: Value| -> usize {
        if v.is_undefined() || v.is_none() { 0 } else { v.len().unwrap_or(0) }
    });
    // Django pluralize: n==1 → singular (default ""), else plural (default "s");
    // `|pluralize:"y,ies"` gives explicit singular/plural suffixes.
    env.add_filter("pluralize", |v: Value, suffix: Option<String>| -> String {
        let n = i64::try_from(v.clone()).ok().or_else(|| v.len().map(|l| l as i64)).unwrap_or(0);
        let (sing, plur) = match suffix.as_deref() {
            Some(s) if s.contains(',') => {
                let mut it = s.splitn(2, ',');
                (it.next().unwrap_or("").to_string(), it.next().unwrap_or("").to_string())
            }
            Some(s) => (String::new(), s.to_string()),
            None => (String::new(), "s".to_string()),
        };
        if n == 1 { sing } else { plur }
    });
    env.add_filter("chanslug", |name: String| -> String {
        name.trim_start_matches(['@', '+', '%', '&', '~'])
            .strip_prefix('#')
            .map(str::to_string)
            .unwrap_or_else(|| name.trim_start_matches(['@', '+', '%', '&', '~']).to_string())
    });
    env.add_filter("flag", |code: String| -> Value {
        let cc = code.trim();
        if cc.len() != 2 || !cc.chars().all(|c| c.is_ascii_alphabetic()) {
            return Value::from_safe_string("<span class=\"up-flag-x\">🏳️</span>".into());
        }
        let lower = cc.to_ascii_lowercase();
        let emo: String = cc.to_ascii_uppercase().chars()
            .map(|c| char::from_u32(0x1F1E6 + (c as u32 - 'A' as u32)).unwrap_or('?'))
            .collect();
        Value::from_safe_string(format!(
            "<img class=\"up-flag\" src=\"https://flagcdn.com/24x18/{lower}.png\" \
             srcset=\"https://flagcdn.com/48x36/{lower}.png 2x\" width=\"20\" height=\"15\" \
             alt=\"{up}\" loading=\"lazy\" decoding=\"async\" \
             onerror=\"this.outerHTML='<span class=&quot;up-flag-x&quot;>{emo}</span>'\">",
            up = cc.to_ascii_uppercase()
        ))
    });
    env.add_filter("humandt", |v: Value| -> String { fmt_dt(&v, "d/m/Y · H:i").unwrap_or_else(|| dash(&v)) });
    env.add_filter("humanago", |v: Value| -> String { human_ago(&v).unwrap_or_default() });
    env.add_filter("date", |v: Value, fmt: String| -> String { fmt_dt(&v, &fmt).unwrap_or_else(|| dash(&v)) });
    env
}

fn add_dir(env: &mut Environment<'static>, dir: &'static Dir) {
    for f in dir.files() {
        if f.path().extension().and_then(|e| e.to_str()) == Some("html") {
            let name = f.path().to_string_lossy().to_string();
            let src = String::from_utf8_lossy(f.contents()).into_owned();
            if let Err(e) = env.add_template_owned(name.clone(), djangoish(&src)) {
                eprintln!("PANEL TEMPLATE ADD FAIL {name}: {e:#}");
            }
        }
    }
    for d in dir.dirs() {
        add_dir(env, d);
    }
}

/// Map a Django route name (+ optional arg) to the panel's axum path.
fn django_url(name: String, rest: Rest<Value>) -> String {
    let arg = rest.first().map(|v| v.to_string());
    let n = name.strip_prefix("ircpanel:").unwrap_or(&name);
    match (n, arg.as_deref()) {
        ("dashboard", _) => "/".into(),
        ("channel_detail", Some(a)) => format!("/channels/{a}"),
        ("server_detail", Some(a)) => format!("/servers/{a}"),
        ("user_detail", Some(a)) => format!("/users/{a}"),
        ("name_bans", _) => "/name-bans".into(),
        ("security_groups", _) => "/security-groups".into(),
        ("ip_whois", _) => "/ip-whois".into(),
        ("set_language", _) => "/set-language".into(),
        // everything else: /<name> with underscores kept (routes match these)
        (other, _) => format!("/{other}"),
    }
}

// ── Django template dialect → minijinja ─────────────────────────────────────
fn djangoish(src: &str) -> String {
    use regex::Regex;
    use std::sync::OnceLock;
    macro_rules! re {
        ($p:expr) => {{
            static R: OnceLock<Regex> = OnceLock::new();
            R.get_or_init(|| Regex::new($p).unwrap())
        }};
    }
    let mut s = src.to_string();
    s = re!(r"\{%\s*load[^%]*?%\}").replace_all(&s, "").into_owned();
    s = re!(r"\{%\s*(?:end)?spaceless\s*%\}").replace_all(&s, "").into_owned();
    s = s.replace(
        "{% csrf_token %}",
        r#"<input type="hidden" name="csrfmiddlewaretoken" value="{{ csrf_token }}">"#,
    );
    s = re!(r"\{%\s*static\s+'([^']+)'\s*%\}").replace_all(&s, "{{ static_url('$1') }}").into_owned();
    s = re!(r#"\{%\s*static\s+"([^"]+)"\s*%\}"#).replace_all(&s, "{{ static_url(\"$1\") }}").into_owned();
    // {% include "X" with a=b c=d %} → {% set a = b %}…{% include "X" %} (minijinja's
    // include takes no inline context). Python True/False/None → true/false/none.
    s = re!(r#"\{%\s*include\s+("[^"]+")\s+with\s+([^%]+?)\s*%\}"#)
        .replace_all(&s, |c: &regex::Captures| {
            let sets: String = c[2]
                .split_whitespace()
                .map(|p| {
                    let (k, v) = p.split_once('=').unwrap_or((p, ""));
                    let v = match v {
                        "True" => "true",
                        "False" => "false",
                        "None" => "none",
                        other => other,
                    };
                    format!("{{% set {k} = {v} %}}")
                })
                .collect();
            format!("{sets}{{% include {} %}}", &c[1])
        })
        .into_owned();
    // blocktrans → set alias; drop the wrapper (i18n text kept as-is)
    s = re!(r"\{%\s*blocktrans\s+with\s+([^%]+?)\s*%\}").replace_all(&s, "{% set $1 %}").into_owned();
    s = re!(r"\{%\s*(?:end)?blocktrans\s*%\}").replace_all(&s, "").into_owned();
    s = re!(r#"\{%\s*trans\s+"([^"]*)"\s*%\}"#).replace_all(&s, "$1").into_owned();
    s = re!(r"\{%\s*trans\s+'([^']*)'\s*%\}").replace_all(&s, "$1").into_owned();
    s = re!(r"\{%\s*widthratio\s+(\S+)\s+(\S+)\s+(\S+)\s*%\}")
        .replace_all(&s, "{{ widthratio($1, $2, $3) }}").into_owned();
    s = re!(r"\{%\s*url\s+'([^']+)'\s+([^%]+?)\s*%\}").replace_all(&s, "{{ url('$1', $2) }}").into_owned();
    s = re!(r"\{%\s*url\s+'([^']+)'\s*%\}").replace_all(&s, "{{ url('$1') }}").into_owned();
    s = re!(r"\{%\s*empty\s*%\}").replace_all(&s, "{% else %}").into_owned();
    s = s.replace("forloop.counter0", "loop.index0")
        .replace("forloop.counter", "loop.index")
        .replace("forloop.revcounter", "loop.revindex")
        .replace("forloop.first", "loop.first")
        .replace("forloop.last", "loop.last");
    // filter colon-args: |name:arg → |name(arg)
    s = re!(r#"\|(\w+):("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s|%}]+)"#)
        .replace_all(&s, "|$1($2)").into_owned();
    s
}

// ── datetime helpers (unix seconds or ISO string) ───────────────────────────
fn dash(v: &Value) -> String {
    match v.as_str() {
        Some("") | None => "—".into(),
        Some(x) => x.into(),
    }
}

/// Parse a Value into unix seconds: an integer, or an ISO-8601 `YYYY-MM-DDTHH:MM:SS`.
fn to_unix(v: &Value) -> Option<i64> {
    if let Ok(n) = i64::try_from(v.clone()) {
        return Some(n);
    }
    let s = v.as_str()?;
    if let Ok(n) = s.parse::<i64>() {
        return Some(n);
    }
    let (date, time) = s.split_once('T').or_else(|| s.split_once(' '))?;
    let mut d = date.split('-');
    let (y, mo, da): (i64, i64, i64) = (d.next()?.parse().ok()?, d.next()?.parse().ok()?, d.next()?.parse().ok()?);
    let t = time.trim_end_matches('Z');
    let mut tp = t.split(':');
    let (h, mi): (i64, i64) = (tp.next()?.parse().ok()?, tp.next()?.parse().ok()?);
    let se: i64 = tp.next().and_then(|x| x.split('.').next()).and_then(|x| x.parse().ok()).unwrap_or(0);
    // civil date → days since epoch (Howard Hinnant)
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = if yy >= 0 { yy } else { yy - 399 } / 400;
    let yoe = yy - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + da - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + h * 3600 + mi * 60 + se)
}

fn civil(secs: i64) -> (i64, i64, i64, i64, i64, i64) {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d, rem / 3600, (rem % 3600) / 60, rem % 60)
}

/// Format like Django's `date` filter for the specs the templates use (d/m/Y/H/i/s).
fn fmt_dt(v: &Value, fmt: &str) -> Option<String> {
    let (y, mo, d, h, mi, se) = civil(to_unix(v)?);
    let mut out = String::new();
    for c in fmt.chars() {
        match c {
            'd' => out.push_str(&format!("{d:02}")),
            'm' => out.push_str(&format!("{mo:02}")),
            'Y' => out.push_str(&format!("{y:04}")),
            'H' => out.push_str(&format!("{h:02}")),
            'i' => out.push_str(&format!("{mi:02}")),
            's' => out.push_str(&format!("{se:02}")),
            other => out.push(other),
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every page template must render through the Django→minijinja converter with a
    // representative context — this catches any unconverted tag/filter at once.
    #[test]
    fn all_page_templates_render() {
        let ctx = Value::from_serialize(&serde_json::json!({
            "brand": "echo", "active": "", "asset_version": "1", "current_language": "fr",
            "panel_languages": [], "panel_perms": ["audit"], "is_root": true, "csrf_token": "t",
            "request": { "user": { "username": "admin" }, "csp_nonce": "", "get_full_path": "/" },
            "stats": { "me": { "name": "net", "version": "v1" },
                       "user": { "total": 3, "local": 2, "oper": 1 },
                       "channel": { "total": 5 }, "server": { "total": 1 } },
            "servers": [], "top_channels": [], "recent_audit": [], "geo_rows": [], "geo_dots": [],
            "geo_total": 0, "geo_local": 0, "geo_max": 1, "sparks": {}, "world_svg": "",
            "live_url": "/", "ban_count": 0, "messages": [], "err": null,
        }));
        for tpl in [
            "dashboard", "users", "channels", "servers", "trends", "bans", "name_bans",
            "exceptions", "spamfilter", "security_groups", "ip_whois", "whowas", "logs",
            "opers", "registrations", "modules", "audit", "access",
            "user_detail", "channel_detail", "server_detail",
        ] {
            let name = format!("ircpanel/{tpl}.html");
            let out = render(&name, ctx.clone());
            assert!(out.is_ok(), "render {name} failed: {:?}", out.as_ref().err());
            assert!(out.unwrap().contains('<'), "{name} produced no HTML");
        }
    }

    #[test]
    fn static_assets_embedded() {
        for (path, ct) in [
            ("css/theme.css", "text/css"),
            ("css/ircpanel.css", "text/css"),
            ("js/ircpanel.js", "application/javascript"),
        ] {
            let (bytes, ctype) = asset(path).unwrap_or_else(|| panic!("missing asset {path}"));
            assert!(!bytes.is_empty(), "{path} empty");
            assert!(ctype.starts_with(ct), "{path} wrong content-type: {ctype}");
        }
        assert!(asset("nope.css").is_none());
    }
}

fn human_ago(v: &Value) -> Option<String> {
    let then = to_unix(v)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    let s = (now - then).max(0);
    Some(if s < 60 {
        "à l'instant".into()
    } else if s < 3600 {
        format!("il y a {} min", s / 60)
    } else if s < 86400 {
        format!("il y a {} h", s / 3600)
    } else if s < 2_592_000 {
        format!("il y a {} j", s / 86400)
    } else if s < 31_536_000 {
        format!("il y a {} mois", s / 2_592_000)
    } else {
        let yrs = s / 31_536_000;
        format!("il y a {yrs} an{}", if yrs > 1 { "s" } else { "" })
    })
}
