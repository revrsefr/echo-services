//! A tiny DICT-protocol (RFC 2229) client used by DictServ. Runs off the reactor
//! (spawned from the link layer), connects to a DICT server, asks for one
//! definition, and returns a single truncated line to speak into the channel. The
//! response parser is split out so it can be tested without a network.

use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const TIMEOUT: Duration = Duration::from_secs(6);
const MAX_LEN: usize = 400; // keep a spoken reply to about one IRC line

// Look `word` up in `database` on `server`. Never errors out to the caller: on a
// timeout, connection failure, or no match it returns a short human message, so
// the bot always has something safe to say.
pub async fn lookup(server: &str, database: &str, word: &str) -> String {
    let word = sanitize(word);
    if word.is_empty() {
        return "nothing to look up.".to_string();
    }
    match tokio::time::timeout(TIMEOUT, exchange(server, database, &word)).await {
        Ok(Ok(Some(def))) => def,
        Ok(Ok(None)) => format!("no definition found for \x02{word}\x02."),
        Ok(Err(_)) | Err(_) => "the dictionary is unavailable right now.".to_string(),
    }
}

// One request/response round trip. Returns the first definition's text, or None
// for a clean "no match".
async fn exchange(server: &str, database: &str, word: &str) -> std::io::Result<Option<String>> {
    let stream = TcpStream::connect(server).await?;
    stream.set_nodelay(true).ok();
    let (rd, mut wr) = stream.into_split();
    let mut lines = BufReader::new(rd).lines();
    // Banner (220 …).
    lines.next_line().await?;
    wr.write_all(format!("DEFINE {database} \"{word}\"\r\n").as_bytes()).await?;
    let mut raw = String::new();
    while let Some(line) = lines.next_line().await? {
        // 250 ends the whole response; stop reading once we've seen it.
        if line.starts_with("250 ") {
            break;
        }
        raw.push_str(&line);
        raw.push('\n');
        if raw.len() > MAX_LEN * 8 {
            break; // guard against a runaway server
        }
    }
    let _ = wr.write_all(b"QUIT\r\n").await;
    Ok(parse_definition(&raw))
}

// Extract the first definition's body from a DICT DEFINE response. `raw` is the
// lines after the `DEFINE` command (excluding the final 250). Returns None for a
// no-match (552) or an empty body.
fn parse_definition(raw: &str) -> Option<String> {
    let mut body = String::new();
    let mut in_def = false;
    for line in raw.lines() {
        if !in_def {
            match line.get(..3) {
                Some("552") | Some("550") | Some("551") => return None, // no match / bad db
                Some("151") => in_def = true, // start of the first definition block
                _ => {}                       // 220 banner, 150 count, …
            }
            continue;
        }
        // Body runs until a lone "." — take just the first definition.
        if line == "." {
            break;
        }
        let text = line.strip_prefix("..").unwrap_or(line).trim(); // undo dot-stuffing
        if !text.is_empty() {
            if !body.is_empty() {
                body.push(' ');
            }
            body.push_str(text);
        }
        if body.len() >= MAX_LEN {
            break;
        }
    }
    let body: String = body.split_whitespace().collect::<Vec<_>>().join(" ");
    if body.is_empty() {
        return None;
    }
    Some(truncate(&body, MAX_LEN))
}

// A user-supplied term: drop control chars and quotes (which would break the DICT
// quoting), and cap the length so a giant term can't be smuggled to the server.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_first_definition() {
        let raw = "150 2 definitions retrieved\n\
                   151 \"cat\" wn \"WordNet (r) 3.0\"\n\
                   cat\n    n 1: feline mammal usually having thick soft fur\n    n 2: an informal term for a youth or man\n\
                   .\n\
                   151 \"cat\" gcide \"GCIDE\"\n\
                   Cat \\Cat\\ another definition\n\
                   .\n";
        let def = parse_definition(raw).expect("a definition");
        assert!(def.contains("feline mammal"), "got: {def}");
        assert!(!def.contains("GCIDE"), "should stop at the first block: {def}");
    }

    #[test]
    fn no_match_returns_none() {
        assert!(parse_definition("552 no match\n").is_none());
        assert!(parse_definition("150 0 definitions retrieved\n").is_none());
    }

    #[test]
    fn truncates_long_bodies() {
        let long = format!("151 \"x\" wn \"d\"\n{}\n.\n", "word ".repeat(300));
        let def = parse_definition(&long).unwrap();
        assert!(def.chars().count() <= MAX_LEN + 1, "len {}", def.chars().count());
        assert!(def.ends_with('…'));
    }

    #[test]
    fn sanitize_strips_quotes_and_controls() {
        assert_eq!(sanitize("he\"llo\u{1}"), "hello");
        assert_eq!(sanitize("  spaced  "), "spaced");
    }
}
