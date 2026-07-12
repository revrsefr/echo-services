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
