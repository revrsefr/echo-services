// InspIRCd spanning-tree link protocol. Handshake + UID + PING mirror the
// sequence in Network-Links (protocols/inspircd.py); mode/burst details get
// firmed up against a live insp4 uplink.
use super::{NetAction, NetEvent, Protocol};

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
            "QUIT" => vec![NetEvent::Quit { uid: source.unwrap_or_default() }],
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
            NetAction::Raw(s) => vec![s.clone()],
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
