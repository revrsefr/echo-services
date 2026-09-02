//! Translation-catalog guards, run as `cargo test`. These keep the shipped
//! `lang/<code>.json` catalogs complete and consistent with the source, so a
//! stray English edit or a dropped placeholder fails the build instead of
//! silently degrading a language at runtime.

use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

// Modules kept intentionally English-only (staff/dev tools), excluded from the
// source-coverage check.
const ENGLISH_ONLY: &[&str] = &["debugserv", "example"];

fn load_catalogs() -> HashMap<String, HashMap<String, String>> {
    let dir = PathBuf::from(ROOT).join("lang");
    let mut out = HashMap::new();
    for entry in fs::read_dir(&dir).expect("read lang/") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let code = path.file_stem().unwrap().to_str().unwrap().to_string();
        let data = fs::read_to_string(&path).unwrap();
        let map: HashMap<String, String> =
            serde_json::from_str(&data).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        out.insert(code, map);
    }
    assert!(!out.is_empty(), "no catalogs found in lang/");
    out
}

/// The sorted multiset of `{...}` tokens in a string.
fn placeholders(s: &str) -> Vec<&str> {
    let mut v = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            if let Some(rel) = s[i..].find('}') {
                v.push(&s[i..i + rel + 1]);
                i += rel + 1;
                continue;
            }
        }
        i += 1;
    }
    v.sort_unstable();
    v
}

/// Every translation must carry exactly the same `{placeholder}` tokens as its
/// English key — otherwise a substitution silently no-ops or leaks a raw token.
#[test]
fn placeholder_parity() {
    let cats = load_catalogs();
    let mut bad = Vec::new();
    for (code, map) in &cats {
        for (key, val) in map {
            if placeholders(key) != placeholders(val) {
                bad.push(format!("[{code}] {key:?}\n        -> {val:?}"));
            }
        }
    }
    assert!(bad.is_empty(), "placeholder mismatches:\n{}", bad.join("\n"));
}

/// All translation catalogs must cover the exact same set of message ids, so no
/// language quietly lags behind another. `en.json` is exempt: it's an optional
/// English OVERRIDE catalog (English otherwise defaults to the msgid itself), so it
/// legitimately holds only the subset of strings an operator chooses to change.
#[test]
fn catalogs_share_one_keyset() {
    let cats = load_catalogs();
    let reference: HashSet<&String> = cats
        .iter()
        .find(|(code, _)| code.as_str() != "en")
        .expect("a non-en catalog")
        .1
        .keys()
        .collect();
    let mut problems = Vec::new();
    for (code, map) in &cats {
        if code == "en" {
            continue; // override catalog: any subset is allowed
        }
        let keys: HashSet<&String> = map.keys().collect();
        let missing = reference.difference(&keys).count();
        let extra = keys.difference(&reference).count();
        if missing != 0 || extra != 0 {
            problems.push(format!("[{code}] missing {missing}, extra {extra}"));
        }
    }
    assert!(problems.is_empty(), "catalog keysets differ:\n{}", problems.join("\n"));
}

/// Turn a Rust string literal's escape sequences into the runtime message id, so
/// scraped templates match the catalog keys byte for byte.
fn unescape(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some((_, 'x')) => {
                let hex = &s[i + 2..i + 4];
                out.push(u8::from_str_radix(hex, 16).unwrap() as char);
                chars.next(); // skip the two hex digits
                chars.next();
            }
            Some((_, 'n')) => out.push('\n'),
            Some((_, 't')) => out.push('\t'),
            Some((_, 'r')) => out.push('\r'),
            Some((_, '0')) => out.push('\0'),
            Some((_, other)) => out.push(other),
            None => {}
        }
    }
    out
}

fn module_sources() -> Vec<PathBuf> {
    let mut files = Vec::new();
    let modules = PathBuf::from(ROOT).join("modules");
    let mut stack = vec![modules];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
                if ENGLISH_ONLY.contains(&name) {
                    continue;
                }
                stack.push(path);
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                files.push(path);
            }
        }
    }
    files
}

/// Every `t!` and `plural!` template used in a translated module must exist in
/// the reference catalog, so a new user-facing string can't ship untranslated.
#[test]
fn every_template_is_translated() {
    let cats = load_catalogs();
    // Any catalog works as the reference — `catalogs_share_one_keyset` proves
    // they agree; use French, the network default.
    let reference = cats.get("fr").expect("fr catalog");
    let str_lit = r#""((?:[^"\\]|\\.)*)""#;
    let t_re = Regex::new(&format!(r"\bt!\s*\(\s*ctx\s*,\s*{str_lit}")).unwrap();
    let plural_re =
        Regex::new(&format!(r"(?s)plural!\s*\(\s*ctx\s*,.*?one\s*=\s*{str_lit}\s*,\s*other\s*=\s*{str_lit}")).unwrap();

    let mut missing = Vec::new();
    for path in module_sources() {
        let src = fs::read_to_string(&path).unwrap();
        let rel = path.strip_prefix(ROOT).unwrap_or(&path).display().to_string();
        for cap in t_re.captures_iter(&src) {
            let id = unescape(&cap[1]);
            if !reference.contains_key(&id) {
                missing.push(format!("{rel}: t! {id:?}"));
            }
        }
        for cap in plural_re.captures_iter(&src) {
            for g in [1usize, 2] {
                let id = unescape(&cap[g]);
                if !reference.contains_key(&id) {
                    missing.push(format!("{rel}: plural! {id:?}"));
                }
            }
        }
    }
    // Also guard the engine- and email-layer strings, which localise via
    // echo_api::render / crate::render (with a literal msgid) rather than the
    // module macros. Scoped to those call prefixes so email.rs's own private
    // `render` HTML helper and test literals aren't picked up.
    let render_re =
        Regex::new(&format!(r"(?:echo_api|crate)::render\s*\(\s*[^,]+,\s*{str_lit}")).unwrap();
    let render_plural_re = Regex::new(&format!(
        r"(?:echo_api|crate)::render_plural\s*\(\s*[^,]+,\s*[^,]+,\s*{str_lit}\s*,\s*{str_lit}"
    ))
    .unwrap();
    let mut extra = vec![PathBuf::from(ROOT).join("api/src/email.rs")];
    let mut stack = vec![PathBuf::from(ROOT).join("src/engine")];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().and_then(|s| s.to_str()) == Some("rs")
                && p.file_name().and_then(|s| s.to_str()) != Some("tests.rs")
            {
                extra.push(p);
            }
        }
    }
    for path in extra {
        let Ok(src) = fs::read_to_string(&path) else { continue };
        let rel = path.strip_prefix(ROOT).unwrap_or(&path).display().to_string();
        for cap in render_re.captures_iter(&src) {
            let id = unescape(&cap[1]);
            if !reference.contains_key(&id) {
                missing.push(format!("{rel}: render {id:?}"));
            }
        }
        for cap in render_plural_re.captures_iter(&src) {
            for g in [1usize, 2] {
                let id = unescape(&cap[g]);
                if !reference.contains_key(&id) {
                    missing.push(format!("{rel}: render_plural {id:?}"));
                }
            }
        }
    }

    assert!(
        missing.is_empty(),
        "these templates have no catalog entry:\n{}",
        missing.join("\n")
    );
}
