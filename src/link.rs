use std::borrow::Cow;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

use crate::engine::db::Db;
use crate::engine::Engine;
use crate::proto::{NetAction, Protocol};

// The uplink socket, plaintext or TLS. Both inner types are Unpin, so projecting
// the pin is a plain re-pin of the inner stream.
enum UplinkStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for UplinkStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            UplinkStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            UplinkStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for UplinkStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            UplinkStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            UplinkStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            UplinkStream::Plain(s) => Pin::new(s).poll_flush(cx),
            UplinkStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            UplinkStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            UplinkStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

// Cap on one uplink line (well above IRC's 512 + generous room for message tags),
// so a misbehaving uplink can't grow an unbounded read buffer.
const MAX_UPLINK_LINE: usize = 16 * 1024;

// Read one newline-delimited uplink line, bounded and decoded UTF-8-LOSSILY. IRC is
// byte-oriented and any user's PRIVMSG relayed to a service can carry raw non-UTF-8
// bytes; the old `.lines()` returned an Err on those, which propagated out of the
// reactor and CRASHED the whole daemon. `None` on EOF; io::Error only on a genuine
// read failure. Bytes past the cap are dropped until the newline.
async fn read_uplink_line<R: tokio::io::AsyncRead + Unpin>(reader: &mut R, max: usize) -> std::io::Result<Option<String>> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if reader.read(&mut byte).await? == 0 {
            return Ok((!buf.is_empty()).then(|| decode_uplink_line(&buf)));
        }
        if byte[0] == b'\n' {
            return Ok(Some(decode_uplink_line(&buf)));
        }
        if buf.len() < max {
            buf.push(byte[0]);
        }
    }
}

fn decode_uplink_line(buf: &[u8]) -> String {
    String::from_utf8_lossy(buf.strip_suffix(b"\r").unwrap_or(buf)).into_owned()
}

// NickServ commands whose arguments are a password and must never be logged.
const SECRET_CMDS: &[&str] = &[
    "identify", "id", "login", "auth", "register", "regain", "ghost", "release",
    "recover", "setpass", "spassword", "resetpass", "confirm", "sidentify",
];

/// Scrub credentials from a raw IRC line before it is debug-logged: NickServ
/// identify/register/password arguments and SASL payloads. Best-effort and
/// deliberately over-redacting — a logged line must never carry a secret.
fn redact(line: &str) -> Cow<'_, str> {
    // A password carried in a PRIVMSG/NOTICE/SQUERY message trailer.
    for kw in [" PRIVMSG ", " NOTICE ", " SQUERY "] {
        if let Some(p) = line.find(kw) {
            let after = p + kw.len();
            if let Some(c) = line[after..].find(" :") {
                let tstart = after + c + 2;
                // Tokenise the trailer exactly like the dispatcher (`split_whitespace`),
                // so a TAB or a leading/collapsed space can't sneak a credential past
                // redaction while still reaching the command handler.
                let mut words = line[tstart..].split_whitespace();
                let mut cmd = words.next().unwrap_or("").to_ascii_lowercase();
                // "NS <cmd> ..." / "NICKSERV <cmd> ..." — unwrap one level.
                if matches!(cmd.as_str(), "ns" | "nickserv") {
                    cmd = words.next().unwrap_or("").to_ascii_lowercase();
                }
                let is_set_password = cmd == "set"
                    && words.next().map(|w| w.eq_ignore_ascii_case("password")).unwrap_or(false);
                // Over-redact the whole trailer when the command is credential-bearing.
                if SECRET_CMDS.contains(&cmd.as_str()) || is_set_password {
                    return format!("{} :[REDACTED]", line[..tstart].trim_end_matches(" :")).into();
                }
            }
        }
    }
    // SASL: "AUTHENTICATE <data>" and server "... SASL <a> <b> C|S <data>". The
    // payload token is the credential; mechanism/control tokens are harmless.
    if let Some(p) = line.find("AUTHENTICATE ") {
        let d = p + "AUTHENTICATE ".len();
        let tok = line[d..].split(' ').next().unwrap_or("");
        if !matches!(tok, "+" | "*" | "") && !tok.starts_with("PLAIN") && !tok.starts_with("EXTERNAL") && !tok.starts_with("SCRAM") {
            return format!("{}[REDACTED]", &line[..d]).into();
        }
    }
    if let Some(p) = line.find(" SASL ") {
        for mode in [" C ", " S "] {
            if let Some(m) = line[p..].find(mode) {
                let d = p + m + mode.len();
                let tok = line[d..].split(' ').next().unwrap_or("");
                if !tok.is_empty() && tok != "+" {
                    return format!("{}[REDACTED]", &line[..d]).into();
                }
            }
        }
    }
    Cow::Borrowed(line)
}

// One uplink session: connect, handshake + burst, then translate lines forever.
// The engine is shared with the gossip layer, so it is locked per operation and
// never held across the registration key-stretching await.
#[allow(clippy::too_many_arguments)] // the link driver legitimately wires up many collaborators
pub async fn run(mut proto: Box<dyn Protocol>, engine: Arc<Mutex<Engine>>, addr: &str, tls: Option<(TlsConnector, ServerName<'static>)>, mut irc_rx: mpsc::UnboundedReceiver<NetAction>, irc_tx: mpsc::UnboundedSender<NetAction>, email: Option<crate::config::Email>, keycard: Option<crate::config::Keycard>, dict_server: Option<String>) -> Result<()> {
    let tcp = TcpStream::connect(addr).await?;
    // Disable Nagle: service replies are small multi-line bursts, and without this
    // the last segment of a reply is held ~40ms waiting on a delayed ACK, so a
    // HELP visibly lags before it lands. Every ircd sets this on every socket.
    tcp.set_nodelay(true)?;
    // Wrap in TLS (SPKI-pinned) when configured; otherwise stay plaintext.
    let stream = match tls {
        Some((connector, name)) => UplinkStream::Tls(Box::new(connector.connect(name, tcp).await?)),
        None => UplinkStream::Plain(tcp),
    };
    let (read, write) = tokio::io::split(stream);
    let mut write = write;
    let mut reader = BufReader::new(read);

    for line in proto.handshake() {
        send(&mut write, &line).await?;
    }
    let startup = engine.lock().await.startup_actions();
    for action in startup {
        for line in proto.serialize(&action) {
            send(&mut write, &line).await?;
        }
    }

    loop {
        tokio::select! {
            // A line from the uplink: translate it and answer.
            line = read_uplink_line(&mut reader, MAX_UPLINK_LINE) => {
                let Some(line) = line? else { break };
                tracing::debug!(dir = "<<", line = %redact(&line));
                for event in proto.parse(&line) {
                    let actions = engine.lock().await.handle(event);
                    for action in actions {
                        let outs = match action {
                            // Registration: derive the password off the reactor so the
                            // ~1s of key stretching can't stall the link, after a cheap
                            // gate that rejects taken names and rate-limits floods.
                            NetAction::DeferRegister { account, password, email, reply } => {
                                let pre = engine.lock().await.pre_register_check(&account, &reply);
                                match pre {
                                    Some(rejection) => rejection,
                                    None => {
                                        let iterations = engine.lock().await.scram_iterations();
                                        let creds = tokio::task::spawn_blocking(move || {
                                            Db::derive_credentials(&password, iterations)
                                        })
                                        .await?;
                                        engine.lock().await.complete_register(&account, creds, email, reply)
                                    }
                                }
                            }
                            // Password change: same off-thread derivation as register.
                            NetAction::DeferPassword { account, password, agent, uid } => {
                                let iterations = engine.lock().await.scram_iterations();
                                let creds = tokio::task::spawn_blocking(move || {
                                    Db::derive_credentials(&password, iterations)
                                })
                                .await?;
                                engine.lock().await.complete_password_change(&account, creds, &agent, &uid)
                            }
                            // Password verify (IDENTIFY / SASL PLAIN): run the ~1s
                            // PBKDF2 off the reactor, then finish under the lock.
                            NetAction::DeferAuthenticate { verifier, password, then } => {
                                let ok = tokio::task::spawn_blocking(move || {
                                    crate::engine::scram::verify_plain(crate::engine::scram::Hash::Sha256, &verifier, &password)
                                })
                                .await?;
                                engine.lock().await.complete_authenticate(ok, then)
                            }
                            NetAction::DeferKeycard { token, account, then } => {
                                // Redeem a website login keycard fully OFF the reactor loop: the
                                // localhost HTTP round-trip can take up to ~7s on a slow Django,
                                // and inline-awaiting it here froze ALL uplink processing for that
                                // long. Keycards arrive mid-SASL (no user commands pending), so
                                // completing asynchronously via irc_tx can't reorder anything. A
                                // redeem panic now fails the login instead of crashing the daemon.
                                let (kc, engine2, tx) = (keycard.clone(), engine.clone(), irc_tx.clone());
                                tokio::spawn(async move {
                                    let ok = tokio::task::spawn_blocking(move || crate::keycard::redeem(kc.as_ref(), &account, &token))
                                        .await
                                        .unwrap_or(false);
                                    let actions = engine2.lock().await.complete_authenticate(ok, then);
                                    for a in actions {
                                        let _ = tx.send(a);
                                    }
                                });
                                Vec::new()
                            }
                            // OperServ REHASH: re-read config.toml and apply the
                            // reloadable settings live, reporting back to the oper.
                            NetAction::Rehash { requester, agent } => {
                                engine.lock().await.rehash(&requester, &agent).1
                            }
                            action => vec![action],
                        };
                        for act in outs {
                            if let NetAction::SendEmail { to, subject, text, html } = act {
                                dispatch_email(&email, to, subject, text, html);
                                continue;
                            }
                            if let NetAction::DictLookup { speak_as, target, database, label, query } = act {
                                dispatch_dict(&dict_server, &irc_tx, speak_as, target, database, label, query);
                                continue;
                            }
                            if let NetAction::Shutdown { restart, reason } = act {
                                {
                                    let mut e = engine.lock().await;
                                    e.persist_stats();
                                    e.persist_incidents();
                                }
                                let _ = write.flush().await;
                                shutdown(restart, &reason);
                            }
                            for out in proto.serialize(&act) {
                                send(&mut write, &out).await?;
                            }
                        }
                    }
                }
            }
            // A services-initiated action (e.g. a forced logout after a lost
            // registration conflict), pushed by the engine from the gossip path.
            Some(action) = irc_rx.recv() => {
                if let NetAction::SendEmail { to, subject, text, html } = action {
                    dispatch_email(&email, to, subject, text, html);
                } else if let NetAction::Shutdown { restart, reason } = action {
                    {
                        let mut e = engine.lock().await;
                        e.persist_stats();
                        e.persist_incidents();
                    }
                    let _ = write.flush().await;
                    shutdown(restart, &reason);
                } else {
                    for out in proto.serialize(&action) {
                        send(&mut write, &out).await?;
                    }
                }
            }
        }
    }

    tracing::warn!("uplink closed the connection");
    Ok(())
}

// Run a DictServ lookup off the reactor and speak the result back. The DICT round
// trip (up to a few seconds) must never touch the engine lock; the reply is pushed
// through irc_tx so the link loop writes it like any services-initiated action. A
// #channel target is spoken by the assigned bot (privmsg), a user gets a notice.
fn dispatch_dict(server: &Option<String>, irc_tx: &mpsc::UnboundedSender<NetAction>, speak_as: String, target: String, database: String, label: String, query: String) {
    let tx = irc_tx.clone();
    let server = server.clone();
    tokio::spawn(async move {
        // A `wikt-<lang>` database routes to Wiktionary (rich monolingual
        // definitions) instead of the DICT server; its blocking HTTP call runs on
        // the blocking pool so it never stalls the reactor.
        let result = if let Some(lang) = database.strip_prefix("wikt-") {
            let (lang, word) = (lang.to_string(), query.clone());
            tokio::task::spawn_blocking(move || crate::wiktionary::lookup(&lang, &word))
                .await
                .unwrap_or_else(|_| "the dictionary is unavailable right now.".to_string())
        } else if let Some(server) = server {
            crate::dict::lookup(&server, &database, &query).await
        } else {
            return tracing::warn!("dict lookup requested but no server configured");
        };
        let text = format!("\x02{query}\x02 ({label}): {result}");
        let action = if target.starts_with('#') || target.starts_with('&') {
            NetAction::Privmsg { from: speak_as, to: target, text }
        } else {
            NetAction::Notice { from: speak_as, to: target, text }
        };
        let _ = tx.send(action);
    });
}

// Fire off an email if email is configured: pipe an RFC822 message to the mail
// command on a spawned task, so a slow MTA never stalls the link. With an HTML
// body it's sent as multipart/alternative (HTML + plaintext fallback).
fn dispatch_email(email: &Option<crate::config::Email>, to: String, subject: String, text: String, html: Option<String>) {
    let Some(email) = email.clone() else {
        return tracing::warn!(%to, "email requested but not configured");
    };
    tokio::spawn(async move {
        // Hard backstop against header injection: never let a control char reach
        // the raw SMTP header block, whatever the caller did. Bodies (text/html)
        // may legitimately contain newlines, so only the header values are checked.
        if [to.as_str(), subject.as_str(), email.from.as_str()].iter().any(|s| s.chars().any(char::is_control)) {
            return tracing::warn!(%to, "refusing to send an email with control characters in a header");
        }
        let headers = format!("From: {}\r\nTo: {to}\r\nSubject: {subject}\r\nMIME-Version: 1.0\r\n", email.from);
        let msg = match html {
            Some(html) => {
                // Random per-message boundary so body content can never be mistaken
                // for the delimiter.
                let mut rb = [0u8; 8];
                rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut rb);
                let b = format!("echo-bnd-{:016x}", u64::from_le_bytes(rb));
                format!(
                    "{headers}Content-Type: multipart/alternative; boundary=\"{b}\"\r\n\r\n\
                     --{b}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{text}\r\n\
                     --{b}\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{html}\r\n--{b}--\r\n"
                )
            }
            None => format!("{headers}Content-Type: text/plain; charset=utf-8\r\n\r\n{text}\r\n"),
        };
        let child = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(&email.command)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(e) => return tracing::warn!(%e, "mail command failed to start"),
        };
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(msg.as_bytes()).await;
            let _ = stdin.shutdown().await;
        }
        let _ = child.wait().await;
    });
}

// Stop the process on an operator's SHUTDOWN/RESTART. Every committed change is
// already fsync'd, so exiting loses nothing. A restart exits non-zero so a
// supervisor configured to restart-on-failure (systemd Restart=on-failure)
// brings us straight back; a plain shutdown exits cleanly and stays down.
fn shutdown(restart: bool, reason: &str) -> ! {
    if restart {
        tracing::info!(%reason, "operator requested restart, exiting for supervisor to respawn");
        std::process::exit(2);
    }
    tracing::info!(%reason, "operator requested shutdown, exiting");
    std::process::exit(0);
}

async fn send(write: &mut (impl AsyncWriteExt + Unpin), line: &str) -> Result<()> {
    tracing::debug!(dir = ">>", line = %redact(line));
    write.write_all(line.as_bytes()).await?;
    write.write_all(b"\r\n").await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::redact;

    #[test]
    fn decode_uplink_line_is_lossy_and_strips_cr() {
        assert_eq!(super::decode_uplink_line(b"PING abc\r"), "PING abc");
        // A non-UTF-8 line must decode (lossily), not error — the old `.lines()`
        // returned Err here and crashed the whole daemon.
        assert_eq!(super::decode_uplink_line(b"PRIVMSG x :\xff\xfe hi"), "PRIVMSG x :\u{fffd}\u{fffd} hi");
    }

    #[tokio::test]
    async fn read_uplink_line_survives_bad_utf8_and_bounds_length() {
        use tokio::io::BufReader;
        let data: Vec<u8> = b"NICK a\r\nPRIVMSG NickServ :\xff\xff q\nQUIT\n".to_vec();
        let mut r = BufReader::new(&data[..]);
        let cap = super::MAX_UPLINK_LINE;
        assert_eq!(super::read_uplink_line(&mut r, cap).await.unwrap(), Some("NICK a".to_string()));
        assert_eq!(super::read_uplink_line(&mut r, cap).await.unwrap(), Some("PRIVMSG NickServ :\u{fffd}\u{fffd} q".to_string()), "bad UTF-8 decodes, no crash");
        assert_eq!(super::read_uplink_line(&mut r, cap).await.unwrap(), Some("QUIT".to_string()));
        assert_eq!(super::read_uplink_line(&mut r, cap).await.unwrap(), None, "EOF");
        // An over-long line is truncated to the cap, not accumulated unbounded.
        let long: Vec<u8> = [vec![b'X'; 50], vec![b'\n']].concat();
        let mut r2 = BufReader::new(&long[..]);
        assert_eq!(super::read_uplink_line(&mut r2, 10).await.unwrap().unwrap().len(), 10);
    }

    #[test]
    fn redacts_identify_password() {
        let line = "@time=x;msgid=y :91ZAAAAFQ PRIVMSG 00DAAAAAA :identify reverse hunter2secret!";
        let out = redact(line);
        assert!(!out.contains("hunter2secret"), "password leaked: {out}");
        assert!(!out.contains("reverse"), "account leaked: {out}");
        assert!(out.contains("PRIVMSG 00DAAAAAA :[REDACTED]"), "{out}");
    }

    #[test]
    fn redacts_register_and_ns_prefix_and_set_password() {
        assert!(!redact(":u PRIVMSG NickServ :register mypass a@b.com").contains("mypass"));
        assert!(!redact(":u PRIVMSG X :NS identify topsecret").contains("topsecret"));
        assert!(!redact(":u PRIVMSG NickServ :set password newpw").contains("newpw"));
    }

    #[test]
    fn redacts_sasl_payloads() {
        assert!(!redact("AUTHENTICATE aGVsbG8AdXNlcgBwYXNz").contains("aGVsbG8"));
        assert!(!redact(":91Z ENCAP 00D SASL 91ZAAAAFQ 00DAAAAAA C cGFzc3dvcmQ=").contains("cGFzc3dvcmQ"));
    }

    #[test]
    fn leaves_ordinary_traffic_and_mechanisms_intact() {
        let chat = ":91ZAAAAFQ PRIVMSG #chan :hello everyone identify yourself";
        assert_eq!(redact(chat), chat, "ordinary channel chat must not be mangled");
        assert_eq!(redact("AUTHENTICATE PLAIN"), "AUTHENTICATE PLAIN");
        assert_eq!(redact("AUTHENTICATE +"), "AUTHENTICATE +");
    }
}
