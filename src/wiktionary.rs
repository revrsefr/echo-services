//! Rich monolingual definitions from Wiktionary, used by DictServ's flagship
//! `dict` for languages where dict.org only offers thin bilingual word lists.
//! Runs off the reactor (the link layer calls it from `spawn_blocking`), fetches
//! the rendered page via the MediaWiki `parse` API, and extracts the first few
//! definition list items from the target language's section. The HTML→text
//! extraction is a pure function so it can be tested without a network.

use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(6);
const MAX_LEN: usize = 400; // keep a spoken reply to about one IRC line
const MAX_DEFS: usize = 2; // senses to show (enough to reach the common one)

// The heading a language's own words sit under in that Wiktionary (its autonym).
// Only the wired languages need an entry; others fall back to the whole page.
fn section_name(lang: &str) -> &str {
    match lang {
        "fr" => "Français",
        _ => "",
    }
}

/// Look `word` up in `lang`.wiktionary and return a short spoken reply. Never
/// errors to the caller: a timeout/miss yields a safe human message.
pub fn lookup(lang: &str, word: &str) -> String {
    let word = sanitize(word);
    if word.is_empty() {
        return "nothing to look up.".to_string();
    }
    let unavailable = || "the dictionary is unavailable right now.".to_string();
    let agent = ureq::AgentBuilder::new().timeout(TIMEOUT).build();
    let url = format!("https://{lang}.wiktionary.org/w/api.php");
    let resp = match agent
        .get(&url)
        .query("action", "parse")
        .query("format", "json")
        .query("prop", "text")
        .query("formatversion", "2")
        .query("redirects", "1")
        .query("page", &word)
        .set("User-Agent", "echo-ircservices/1.0 (IRC dictionary lookup)")
        .call()
    {
        Ok(r) => r,
        Err(_) => return unavailable(),
    };
    let body = match resp.into_string() {
        Ok(b) => b,
        Err(_) => return unavailable(),
    };
    // The `parse` API wraps a missing page in an `error` object rather than `parse`.
    let html = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("parse").and_then(|p| p.get("text")).and_then(|t| t.as_str()).map(str::to_string));
    let Some(html) = html else {
        return format!("no definition found for \x02{word}\x02.");
    };
    let defs = parse_definitions(&html, section_name(lang));
    if defs.is_empty() {
        return format!("no definition found for \x02{word}\x02.");
    }
    let joined = defs.into_iter().take(MAX_DEFS).collect::<Vec<_>>().join(" · ");
    // Drop any control chars before this is spoken into a channel.
    let clean: String = joined.chars().filter(|c| !c.is_control()).collect();
    truncate(clean.trim(), MAX_LEN)
}

/// Extract the definition-list items from a rendered Wiktionary page, scoped to
/// the `section` language heading (its autonym) when given. Pure and testable.
fn parse_definitions(html: &str, section: &str) -> Vec<String> {
    // Scope to the target language's section: from its heading id to the next H2,
    // so we never pull another language's entries off the same page.
    let scoped = scope_to_section(html, section);
    // Remove example/quotation/sub-lists (<dl>, <ul>) so only the definition text
    // of each <li> survives; then read the <li> of each <ol>.
    let no_examples = strip_blocks(&strip_blocks(&scoped, "dl"), "ul");
    let mut defs = Vec::new();
    let ol = Regex::new(r"(?s)<ol[^>]*>(.*?)</ol>").unwrap();
    let li = Regex::new(r"(?s)<li[^>]*>(.*?)</li>").unwrap();
    for o in ol.captures_iter(&no_examples) {
        for l in li.captures_iter(&o[1]) {
            let text = clean_text(&l[1]);
            if !text.is_empty() {
                defs.push(text);
            }
        }
    }
    defs
}

fn scope_to_section(html: &str, section: &str) -> String {
    if section.is_empty() {
        return html.to_string();
    }
    let Some(start) = html.find(&format!("id=\"{section}\"")) else {
        return html.to_string();
    };
    let rest = &html[start..];
    // End at the next level-2 heading (another language). MediaWiki wraps H2s in
    // a `mw-heading2` container; skip our own occurrence before searching.
    match rest.get(8..).and_then(|r| r.find("mw-heading2")) {
        Some(end) => rest[..end + 8].to_string(),
        None => rest.to_string(),
    }
}

// Delete every `<tag>…</tag>` block (used to drop nested example/quote lists).
fn strip_blocks(html: &str, tag: &str) -> String {
    Regex::new(&format!(r"(?s)<{tag}[ >].*?</{tag}>"))
        .unwrap()
        .replace_all(html, "")
        .into_owned()
}

// One definition <li>'s inner HTML → plain text: drop tags, footnote markers, and
// HTML entities, then collapse whitespace.
fn clean_text(inner: &str) -> String {
    let no_tags = Regex::new(r"(?s)<[^>]+>").unwrap().replace_all(inner, "");
    let no_refs = Regex::new(r"\[\d+\]").unwrap().replace_all(&no_tags, "");
    let text = unescape(&no_refs);
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

// Decode the HTML entities Wiktionary actually emits (named specials plus numeric
// character references). Text is otherwise literal UTF-8.
fn unescape(s: &str) -> String {
    let named = s
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&nbsp;", " ")
        .replace("&#160;", " ");
    Regex::new(r"&#(x?[0-9A-Fa-f]+);")
        .unwrap()
        .replace_all(&named, |c: &regex::Captures| {
            let raw = &c[1];
            let code = if let Some(hex) = raw.strip_prefix('x').or_else(|| raw.strip_prefix('X')) {
                u32::from_str_radix(hex, 16).ok()
            } else {
                raw.parse().ok()
            };
            code.and_then(char::from_u32).map(String::from).unwrap_or_default()
        })
        .into_owned()
}

// A user-supplied term: drop control chars and quotes, cap the length.
fn sanitize(word: &str) -> String {
    word.chars().filter(|c| !c.is_control() && *c != '"').take(128).collect::<String>().trim().to_string()
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

use regex::Regex;

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = r#"
      <div class="mw-heading mw-heading2"><h2 id="Français">Français</h2></div>
      <div class="mw-heading mw-heading3"><h3 id="Nom_commun">Nom commun</h3></div>
      <ol>
        <li>(Félinologie) <a href="/x">Mammifère</a> carnivore f&#233;lin.
          <dl><dd>Un exemple qu'il faut ignorer.</dd></dl>
        </li>
        <li>(Par extension) <a>Félin</a>.<ul><li>sous-exemple</li></ul></li>
      </ol>
      <div class="mw-heading mw-heading2"><h2 id="Anglais">Anglais</h2></div>
      <ol><li>an english gloss we must not show</li></ol>
    "#;

    #[test]
    fn extracts_french_defs_without_examples_or_other_languages() {
        let defs = parse_definitions(PAGE, "Français");
        assert_eq!(defs.len(), 2, "got {defs:?}");
        assert_eq!(defs[0], "(Félinologie) Mammifère carnivore félin.");
        assert_eq!(defs[1], "(Par extension) Félin.");
        assert!(!defs.iter().any(|d| d.contains("english")), "leaked another language: {defs:?}");
        assert!(!defs.iter().any(|d| d.contains("exemple")), "leaked an example: {defs:?}");
    }

    #[test]
    fn unescape_handles_named_and_numeric() {
        assert_eq!(unescape("a &amp; b &#233;t&#xe9;"), "a & b été");
    }

    #[test]
    fn no_ol_yields_nothing() {
        assert!(parse_definitions("<p>no list here</p>", "Français").is_empty());
    }
}
