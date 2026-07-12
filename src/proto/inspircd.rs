// InspIRCd spanning-tree link protocol. Handshake + UID + PING mirror the
// sequence in Network-Links (protocols/inspircd.py); mode/burst details get
// firmed up against a live insp4 uplink.
use super::{NetAction, NetEvent, Protocol};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct InspIrcd {
    sid: String,
    name: String,
    password: String,
    protocol: u32,
    ts: u64,
}

impl InspIrcd {
    pub fn new(name: String, sid: String, password: String, protocol: u32, ts: u64) -> Self {
        Self { sid, name, password, protocol, ts }
    }

    fn from_us(&self, cmd: String) -> String {
        format!(":{} {}", self.sid, cmd)
    }
}

impl Protocol for InspIrcd {
    fn handshake(&mut self) -> Vec<String> {
        vec![
            format!("CAPAB START {}", self.protocol),
            format!("CAPAB CAPABILITIES :PROTOCOL={}", self.protocol),
            "CAPAB END".to_string(),
            format!("SERVER {} {} {} :{}", self.name, self.password, self.sid, "Federated Services"),
        ]
    }

    fn parse(&mut self, line: &str) -> Vec<NetEvent> {
        // Strip an optional IRCv3 message-tag prefix (@k=v;… ) — insp tags PRIVMSGs
        // with time/msgid, and it sits before the :source.
        let line = match line.strip_prefix('@') {
            Some(rest) => rest.splitn(2, ' ').nth(1).unwrap_or(""),
            None => line,
        };
        let (source, rest) = match line.strip_prefix(':') {
            Some(s) => {
                let mut it = s.splitn(2, ' ');
                (Some(it.next().unwrap_or("").to_string()), it.next().unwrap_or(""))
            }
            None => (None, line),
        };
        let mut tokens = rest.split(' ');
        let cmd = match tokens.next() {
            Some(c) => c,
            None => return vec![],
        };
        match cmd.to_ascii_uppercase().as_str() {
            "SERVER" => vec![NetEvent::Registered],
            "ENDBURST" => vec![NetEvent::EndBurst],
            "PING" => {
                let token = tokens
                    .next()
                    .unwrap_or("")
                    .trim_start_matches(':')
                    .to_string();
                vec![NetEvent::Ping { token, from: source }]
            }
            "PRIVMSG" => {
                let to = tokens.next().unwrap_or("").to_string();
                vec![NetEvent::Privmsg {
                    from: source.unwrap_or_default(),
                    to,
                    text: trailing(rest),
                }]
            }
            // UID <uuid> <nickts> <nick> … — track who's online so services can
            // resolve a sender's current nick.
            "UID" => {
                let a: Vec<&str> = tokens.collect();
                match (a.first(), a.get(2)) {
                    (Some(uid), Some(nick)) => {
                        vec![NetEvent::UserConnect { uid: uid.to_string(), nick: nick.to_string() }]
                    }
                    _ => vec![],
                }
            }
            // :<uid> NICK <newnick> <newts> — keep the sender's current nick
            // fresh, so nick-based commands (IDENTIFY/REGISTER) act on who they
            // are now, not their nick at burst time (e.g. after a guest rename).
            "NICK" => match (source, tokens.next()) {
                (Some(uid), Some(nick)) if !nick.is_empty() => {
                    vec![NetEvent::NickChange { uid, nick: nick.to_string() }]
                }
                _ => vec![],
            },
            // FJOIN <chan> <ts> <modes> [params] :<members> — channel create/burst.
            "FJOIN" => match tokens.next() {
                Some(chan) if !chan.is_empty() => vec![NetEvent::ChannelCreate { channel: chan.to_string() }],
                _ => vec![],
            },
            // :<src> FMODE <chan> <ts> <modes> [params] — a channel mode change.
            // Skip changes we made ourselves so enforcement can't loop.
            "FMODE" => {
                let a: Vec<&str> = tokens.collect();
                match (source.as_deref(), a.first(), a.get(2)) {
                    (Some(src), Some(chan), Some(modes)) if src != self.sid && chan.starts_with('#') => {
                        vec![NetEvent::ChannelModeChange { channel: chan.to_string(), modes: modes.to_string() }]
                    }
                    _ => vec![],
                }
            }
            "QUIT" => vec![NetEvent::Quit { uid: source.unwrap_or_default() }],
            // account-registration relay from an ircd:
            // ACCTREGISTER <reqid> <origin> <kind> <account> <p2> :<p3>
            "ACCTREGISTER" => {
                let a: Vec<&str> = tokens.by_ref().take(5).collect();
                if a.len() == 5 {
                    vec![NetEvent::AccountRequest {
                        reqid: a[0].to_string(),
                        origin: a[1].to_string(),
                        kind: a[2].to_string(),
                        account: a[3].to_string(),
                        p2: a[4].to_string(),
                        p3: trailing(rest),
                    }]
                } else {
                    vec![]
                }
            }
            // ENCAP <target> <subcmd> …  — we only care about relayed SASL:
            // ENCAP <target> SASL <client> <agent> <mode> [data…]
            "ENCAP" => {
                let _target = tokens.next();
                match tokens.next().map(|s| s.to_ascii_uppercase()).as_deref() {
                    Some("SASL") => {
                        let p: Vec<&str> = tokens.collect();
                        if p.len() >= 3 {
                            vec![NetEvent::Sasl {
                                client: p[0].to_string(),
                                agent: p[1].to_string(),
                                mode: p[2].to_string(),
                                data: p[3..].iter().map(|s| s.to_string()).collect(),
                            }]
                        } else {
                            vec![]
                        }
                    }
                    _ => vec![NetEvent::Unknown { line: line.to_string() }],
                }
            }
            _ => vec![NetEvent::Unknown { line: line.to_string() }],
        }
    }

    fn serialize(&mut self, action: &NetAction) -> Vec<String> {
        match action {
            NetAction::Burst => vec![self.from_us(format!("BURST {}", self.ts))],
            NetAction::EndBurst => vec![self.from_us("ENDBURST".to_string())],
            NetAction::Pong { token, from } => {
                let dest = from.clone().unwrap_or_else(|| self.sid.clone());
                vec![self.from_us(format!("PONG {} {}", dest, token))]
            }
            // insp4 UID: uuid nickts nick realhost disphost realuser dispuser ip signonts +modes :gecos
            // (both a real AND a displayed user field — see m_spanningtree/uid.cpp Builder).
            NetAction::IntroduceUser { uid, nick, ident, host, gecos } => vec![self.from_us(format!(
                "UID {uid} {ts} {nick} {host} {host} {ident} {ident} 0.0.0.0 {ts} +i :{gecos}",
                uid = uid, ts = self.ts, nick = nick, host = host, ident = ident, gecos = gecos
            ))],
            NetAction::Privmsg { from, to, text } => {
                vec![format!(":{} PRIVMSG {} :{}", from, to, text)]
            }
            NetAction::Notice { from, to, text } => {
                vec![format!(":{} NOTICE {} :{}", from, to, text)]
            }
            // ACCTREGRESULT <reqid> <kind> <account> <status> <code> :<message>
            NetAction::AccountResponse { reqid, kind, account, status, code, message } => {
                vec![self.from_us(format!(
                    "ACCTREGRESULT {} {} {} {} {} :{}",
                    reqid, kind, account, status, code, message
                ))]
            }
            // ENCAP * SASL <agent> <client> <mode> [data…]
            NetAction::Sasl { agent, client, mode, data } => {
                let mut line = format!("ENCAP * SASL {} {} {}", agent, client, mode);
                for d in data {
                    line.push(' ');
                    line.push_str(d);
                }
                vec![self.from_us(line)]
            }
            // METADATA <target> <key> :<value> — "*" is server-global metadata.
            NetAction::Metadata { target, key, value } => {
                vec![self.from_us(format!("METADATA {} {} :{}", target, key, value))]
            }
            // SVSNICK <uid> <newnick> <nickts> — the new nick takes the current
            // time as its TS so it wins any collision resolution.
            NetAction::ForceNick { uid, nick } => {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(self.ts);
                vec![self.from_us(format!("SVSNICK {} {} {}", uid, nick, now))]
            }
            // FMODE <chan> <ts> <modes>. The ircd drops an FMODE whose TS is newer
            // than the channel's, so we send TS 1 to guarantee it applies to the
            // existing channel. Sourced from our server, which +r requires.
            NetAction::ChannelMode { channel, modes } => {
                vec![self.from_us(format!("FMODE {} 1 {}", channel, modes))]
            }
            NetAction::Raw(s) => vec![s.clone()],
            // Internal: the link layer handles this before serialization.
            NetAction::DeferRegister { .. } => vec![],
        }
    }

    fn sid(&self) -> &str {
        &self.sid
    }
}

// The IRC "trailing" argument: everything after the first " :", else the last word.
fn trailing(rest: &str) -> String {
    match rest.find(" :") {
        Some(i) => rest[i + 2..].to_string(),
        None => rest.rsplit(' ').next().unwrap_or("").to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proto() -> InspIrcd {
        InspIrcd::new("services.test".into(), "42S".into(), "pw".into(), 1206, 1)
    }

    // A remote nick change must surface as a NickChange for the source uid, or
    // nick-based commands act on a stale nick.
    #[test]
    fn parses_nick_change() {
        let ev = proto().parse(":0IRAAAAAB NICK newnick 1783833000");
        assert!(
            matches!(ev.as_slice(), [NetEvent::NickChange { uid, nick }] if uid == "0IRAAAAAB" && nick == "newnick"),
            "{ev:?}"
        );
    }

    // A UID burst introduces the user under their current nick.
    #[test]
    fn parses_uid_burst() {
        let ev = proto().parse(":0IR UID 0IRAAAAAB 1783833000 alice host host user user 0.0.0.0 1783833000 +i :real");
        assert!(
            matches!(ev.as_slice(), [NetEvent::UserConnect { uid, nick }] if uid == "0IRAAAAAB" && nick == "alice"),
            "{ev:?}"
        );
    }

    // FJOIN (channel create/burst) surfaces as ChannelCreate for the channel.
    #[test]
    fn parses_fjoin_as_channel_create() {
        let ev = proto().parse(":0IR FJOIN #chan 1783845132 +tn :o,0IRAAAAAB:0");
        assert!(
            matches!(ev.as_slice(), [NetEvent::ChannelCreate { channel }] if channel == "#chan"),
            "{ev:?}"
        );
    }

    // A peer FMODE surfaces as a mode change; our own (sid 42S) is filtered out.
    #[test]
    fn parses_fmode_and_filters_own() {
        let ev = proto().parse(":0IRAAAAAB FMODE #chan 1783845132 +m");
        assert!(
            matches!(ev.as_slice(), [NetEvent::ChannelModeChange { channel, modes }] if channel == "#chan" && modes == "+m"),
            "{ev:?}"
        );
        let ev = proto().parse(":42S FMODE #chan 1783845132 -m");
        assert!(!ev.iter().any(|e| matches!(e, NetEvent::ChannelModeChange { .. })), "own change filtered: {ev:?}");
    }
}
