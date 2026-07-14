use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};

use crate::engine::db::Db;
use crate::engine::Engine;
use crate::proto::{NetAction, Protocol};

// One uplink session: connect, handshake + burst, then translate lines forever.
// The engine is shared with the gossip layer, so it is locked per operation and
// never held across the registration key-stretching await.
pub async fn run(mut proto: Box<dyn Protocol>, engine: Arc<Mutex<Engine>>, addr: &str, mut irc_rx: mpsc::UnboundedReceiver<NetAction>, email: Option<crate::config::Email>) -> Result<()> {
    let stream = TcpStream::connect(addr).await?;
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
                tracing::debug!(dir = "<<", %line);
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
                            action => vec![action],
                        };
                        for act in outs {
                            if let NetAction::SendEmail { to, subject, text, html } = act {
                                dispatch_email(&email, to, subject, text, html);
                                continue;
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

async fn send(write: &mut (impl AsyncWriteExt + Unpin), line: &str) -> Result<()> {
    tracing::debug!(dir = ">>", %line);
    write.write_all(line.as_bytes()).await?;
    write.write_all(b"\r\n").await?;
    Ok(())
}
