use std::borrow::Cow;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};

use crate::engine::db::Db;
use crate::engine::Engine;
use crate::proto::{NetAction, Protocol};

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
                let mut words = line[tstart..].split(' ');
                let first = words.next().unwrap_or("");
                let mut cmd = first.to_ascii_lowercase();
                let mut argstart = tstart + first.len();
                // "NS <cmd> ..." / "NICKSERV <cmd> ..." — unwrap one level.
                if matches!(cmd.as_str(), "ns" | "nickserv") {
                    if let Some(w2) = words.next() {
                        cmd = w2.to_ascii_lowercase();
                        argstart += 1 + w2.len();
                    }
                }
                let is_set_password = cmd == "set"
                    && words.next().map(|w| w.eq_ignore_ascii_case("password")).unwrap_or(false);
                if (SECRET_CMDS.contains(&cmd.as_str()) || is_set_password) && argstart < line.len() {
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
pub async fn run(mut proto: Box<dyn Protocol>, engine: Arc<Mutex<Engine>>, addr: &str, mut irc_rx: mpsc::UnboundedReceiver<NetAction>, email: Option<crate::config::Email>, keycard: Option<crate::config::Keycard>) -> Result<()> {
    let stream = TcpStream::connect(addr).await?;
    // Disable Nagle: service replies are small multi-line bursts, and without this
    // the last segment of a reply is held ~40ms waiting on a delayed ACK, so a
    // HELP visibly lags before it lands. Every ircd sets this on every socket.
    stream.set_nodelay(true)?;
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();

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
            line = lines.next_line() => {
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
                                // Redeem a website login keycard off the reactor (a localhost
                                // HTTP round-trip), then finish the login under the lock — the
                                // completion is identical to a password auth once we know the
                                // outcome.
                                let kc = keycard.clone();
                                let ok = tokio::task::spawn_blocking(move || {
                                    crate::keycard::redeem(kc.as_ref(), &account, &token)
                                })
                                .await?;
                                engine.lock().await.complete_authenticate(ok, then)
                            }
                            // OperServ REHASH: re-read config.toml and apply the
                            // reloadable settings live, reporting back to the oper.
                            NetAction::Rehash { requester, agent } => {
                                engine.lock().await.rehash(&requester, &agent)
                            }
                            action => vec![action],
                        };
                        for act in outs {
                            if let NetAction::SendEmail { to, subject, text, html } = act {
                                dispatch_email(&email, to, subject, text, html);
                                continue;
                            }
                            if let NetAction::Shutdown { restart, reason } = act {
                                engine.lock().await.persist_stats();
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
                    engine.lock().await.persist_stats();
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

// Fire off an email if email is configured: pipe an RFC822 message to the mail
// command on a spawned task, so a slow MTA never stalls the link. With an HTML
// body it's sent as multipart/alternative (HTML + plaintext fallback).
fn dispatch_email(email: &Option<crate::config::Email>, to: String, subject: String, text: String, html: Option<String>) {
    let Some(email) = email.clone() else {
        return tracing::warn!(%to, "email requested but not configured");
    };
    tokio::spawn(async move {
        let headers = format!("From: {}\r\nTo: {to}\r\nSubject: {subject}\r\nMIME-Version: 1.0\r\n", email.from);
        let msg = match html {
            Some(html) => {
                let b = "echo-alt-boundary-x9";
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
