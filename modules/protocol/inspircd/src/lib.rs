// InspIRCd spanning-tree link protocol. Handshake + UID + PING mirror the
// sequence in Network-Links (protocols/inspircd.py); mode/burst details get
// firmed up against a live insp4 uplink.
use echo_api::{NetAction, NetEvent, Protocol};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct InspIrcd {
    sid: String,
    name: String,
    description: String,
    password: String,
    protocol: u32,
    ts: u64,
    // Monotonic membership id for our own IJOINs. InspIRCd requires a membid on
    // IJOIN (`IJOIN <chan> <membid>`); it need only be unique among our members.
    membid: u64,
}

impl InspIrcd {
    pub fn new(name: String, description: String, sid: String, password: String, protocol: u32, ts: u64) -> Self {
        Self { sid, name, description, password, protocol, ts, membid: 0 }
    }

    fn sourced(&self, cmd: String) -> String {
        format!(":{} {}", self.sid, cmd)
    }
}

impl Protocol for InspIrcd {
    fn handshake(&mut self) -> Vec<String> {
        vec![
            format!("CAPAB START {}", self.protocol),
            format!("CAPAB CAPABILITIES :PROTOCOL={}", self.protocol),
            "CAPAB END".to_string(),
            format!("SERVER {} {} {} :{}", self.name, self.password, self.sid, self.description),
        ]
    }

    fn parse(&mut self, line: &str) -> Vec<NetEvent> {
        // Strip an optional IRCv3 message-tag prefix (@k=v;… ) — insp tags PRIVMSGs
        // with time/msgid, and it sits before the :source.
        let line = match line.strip_prefix('@') {
            Some(rest) => rest.split_once(' ').map(|x| x.1).unwrap_or(""),
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
            // A sourced SERVER ( :<parent> SERVER <name> <sid> [hops] :<desc> ) is a
            // downstream link — track it for the server tree. The unsourced auth
            // handshake ( SERVER <name> <pass> <sid> … ) is our uplink registering.
            "SERVER" => match source {
                Some(parent) => {
                    let _name = tokens.next();
                    match tokens.next() {
                        Some(sid) if !sid.is_empty() => vec![NetEvent::ServerLink { sid: sid.to_string(), parent }],
                        _ => vec![],
                    }
                }
                None => vec![NetEvent::Registered],
            },
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
            // UID <uuid> <nickts> <nick> <realhost> <disphost> <realuser> <dispuser>
            // <ip> <signon> … — take the displayed host for ban masks and the ip
            // (index 7) for session limiting.
            "UID" => {
                let a: Vec<&str> = tokens.collect();
                match (a.first(), a.get(2)) {
                    (Some(uid), Some(nick)) => {
                        let host = a.get(4).unwrap_or(&"").to_string();
                        let ip = a.get(7).unwrap_or(&"").to_string();
                        vec![NetEvent::UserConnect { uid: uid.to_string(), nick: nick.to_string(), host, ip }]
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
            // Each member is "<prefixes>,<uid>"; surface a Join for each.
            "FJOIN" => {
                // Mode section is everything before the " :<members>" trailing.
                let head: Vec<&str> = rest.split(" :").next().unwrap_or(rest).split_whitespace().collect();
                let chan = head.get(1).copied().unwrap_or("");
                if chan.is_empty() {
                    vec![]
                } else {
                    let mut out = vec![NetEvent::ChannelCreate { channel: chan.to_string() }];
                    if let Some(modes) = head.get(3) {
                        if let Some(key) = scan_key(modes, head.get(4..).unwrap_or(&[])) {
                            out.push(NetEvent::ChannelKey { channel: chan.to_string(), key });
                        }
                    }
                    // Members are "<prefixes>,<uid>[:<membid>]"; the prefixes are the
                    // status mode letters, so 'o' means they join opped.
                    for m in trailing(rest).split_whitespace() {
                        if let Some((prefix, member)) = m.split_once(',') {
                            let uid = member.split(':').next().unwrap_or("");
                            if !uid.is_empty() {
                                out.push(NetEvent::Join { uid: uid.to_string(), channel: chan.to_string(), op: prefix.contains('o') });
                                if prefix.contains('v') {
                                    out.push(NetEvent::ChannelVoice { channel: chan.to_string(), uid: uid.to_string(), voice: true });
                                }
                            }
                        }
                    }
                    out
                }
            }
            // :<uid> IJOIN <chan> — a single user joining an existing channel (not opped).
            "IJOIN" => match (source.as_deref(), tokens.next()) {
                (Some(uid), Some(chan)) if chan.starts_with('#') => {
                    vec![NetEvent::Join { uid: uid.to_string(), channel: chan.to_string(), op: false }]
                }
                _ => vec![],
            },
            // :<uid> PART <chan> [:reason] — a user leaving a channel.
            "PART" => match (source.as_deref(), tokens.next()) {
                (Some(uid), Some(chan)) if chan.starts_with('#') => {
                    vec![NetEvent::Part { uid: uid.to_string(), channel: chan.to_string() }]
                }
                _ => vec![],
            },
            // :<src> KICK <chan> <uid> :<reason> — a user removed from a channel.
            "KICK" => {
                let chan = tokens.next().unwrap_or("");
                match tokens.next() {
                    Some(uid) if chan.starts_with('#') => {
                        vec![NetEvent::Part { uid: uid.to_string(), channel: chan.to_string() }]
                    }
                    _ => vec![],
                }
            }
            // :<src> FMODE <chan> <ts> <modes> [params] — a channel mode change.
            // Skip changes we made ourselves so enforcement can't loop.
            "FMODE" => {
                let a: Vec<&str> = tokens.collect();
                match (source.as_deref(), a.first(), a.get(2)) {
                    // Our own uids (server SID + pseudoclients) share our SID prefix.
                    (Some(src), Some(chan), Some(modes)) if !src.starts_with(self.sid.as_str()) && chan.starts_with('#') => {
                        let params = a.get(3..).unwrap_or(&[]);
                        let mut out = vec![NetEvent::ChannelModeChange { channel: chan.to_string(), modes: modes.to_string() }];
                        if let Some(key) = scan_key(modes, params) {
                            out.push(NetEvent::ChannelKey { channel: chan.to_string(), key });
                        }
                        for (op, uid) in scan_status(modes, params, 'o') {
                            out.push(NetEvent::ChannelOp { channel: chan.to_string(), uid, op });
                        }
                        for (voice, uid) in scan_status(modes, params, 'v') {
                            out.push(NetEvent::ChannelVoice { channel: chan.to_string(), uid, voice });
                        }
                        out
                    }
                    _ => vec![],
                }
            }
            // :<src> FTOPIC <chan> <chants> <topicts> [setby] :<topic> — a topic
            // change. Skip changes we made ourselves so enforcement can't loop.
            "FTOPIC" => {
                let a: Vec<&str> = tokens.collect();
                match (source.as_deref(), a.first()) {
                    (Some(src), Some(chan)) if !src.starts_with(self.sid.as_str()) && chan.starts_with('#') => {
                        vec![NetEvent::TopicChange { channel: chan.to_string(), setter: src.to_string(), topic: trailing(rest) }]
                    }
                    _ => vec![],
                }
            }
            // :<src> METADATA <target> <key> :<value> — the ircd sharing user
            // state. We care about `accountname` on a uid (e.g. replayed on our
            // netburst) to restore who is logged in; an empty value is a logout.
            "METADATA" => {
                let a: Vec<&str> = tokens.collect();
                match (source.as_deref(), a.first(), a.get(1)) {
                    (Some(src), Some(target), Some(key))
                        if !src.starts_with(self.sid.as_str())
                            && key.eq_ignore_ascii_case("accountname")
                            && *target != "*" =>
                    {
                        vec![NetEvent::AccountLogin { uid: target.to_string(), account: trailing(rest) }]
                    }
                    _ => vec![],
                }
            }
            "QUIT" => vec![NetEvent::Quit { uid: source.unwrap_or_default() }],
            // :<src> KILL <uid> :<reason> — a user forcibly removed. We forget
            // them (or reintroduce, if it was one of our bots).
            "KILL" => match tokens.next() {
                Some(uid) if !uid.is_empty() => vec![NetEvent::UserKilled { uid: uid.to_string() }],
                _ => vec![],
            },
            // :<src> SQUIT <sid> :<reason> — a server split; forget its users.
            "SQUIT" => match tokens.next() {
                Some(server) if !server.is_empty() => vec![NetEvent::ServerSplit { server: server.to_string() }],
                _ => vec![],
            },
            // ENCAP <target> <subcmd> …  — we care about relayed SASL and the
            // account-registration relay (the ircd's account module forwards a
            // leaf's REGISTER/VERIFY/RESEND/STATUS to us, the authority server).
            "ENCAP" => {
                let _target = tokens.next();
                match tokens.next().map(|s| s.to_ascii_uppercase()).as_deref() {
                    // SWACCTREG <reqid> <origin> <kind> <account> <p2> :<p3>
                    Some("SWACCTREG") => {
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
                    // ENCAP <target> SASL <client> <agent> <mode> [data…]
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
        let lines = match action {
            NetAction::Burst => vec![self.sourced(format!("BURST {}", self.ts))],
            NetAction::EndBurst => vec![self.sourced("ENDBURST".to_string())],
            NetAction::Pong { token, from } => {
                let dest = from.clone().unwrap_or_else(|| self.sid.clone());
                vec![self.sourced(format!("PONG {} {}", dest, token))]
            }
            // insp4 UID: uuid nickts nick realhost disphost realuser dispuser ip signonts +modes :gecos
            // (both a real AND a displayed user field — see m_spanningtree/uid.cpp Builder).
            NetAction::IntroduceUser { uid, nick, ident, host, gecos } => vec![self.sourced(format!(
                "UID {uid} {ts} {nick} {host} {host} {ident} {ident} 0.0.0.0 {ts} +i :{gecos}",
                uid = uid, ts = self.ts, nick = nick, host = host, ident = ident, gecos = gecos
            ))],
            NetAction::Privmsg { from, to, text } => {
                vec![format!(":{} PRIVMSG {} :{}", from, to, text)]
            }
            NetAction::Notice { from, to, text } => {
                vec![format!(":{} NOTICE {} :{}", from, to, text)]
            }
            // Answer the origin server: ENCAP <origin> SWACCTRES <reqid> <kind>
            // <account> <status> <code> :<message>
            NetAction::AccountResponse { reqid, origin, kind, account, status, code, message } => {
                vec![self.sourced(format!(
                    "ENCAP {} SWACCTRES {} {} {} {} {} :{}",
                    origin, reqid, kind, account, status, code, message
                ))]
            }
            // ENCAP * SASL <agent> <client> <mode> [data…]
            NetAction::Sasl { agent, client, mode, data } => {
                let mut line = format!("ENCAP * SASL {} {} {}", agent, client, mode);
                for d in data {
                    line.push(' ');
                    line.push_str(d);
                }
                vec![self.sourced(line)]
            }
            // METADATA <target> <key> :<value> — "*" is server-global metadata.
            NetAction::Metadata { target, key, value } => {
                vec![self.sourced(format!("METADATA {} {} :{}", target, key, value))]
            }
            // SVSNICK <uid> <newnick> <nickts> — the new nick takes the current
            // time as its TS so it wins any collision resolution.
            NetAction::QuitUser { uid, reason } => vec![format!(":{} QUIT :{}", uid, reason)],
            NetAction::ServiceJoin { uid, channel } => {
                // IJOIN needs a membid (`IJOIN <chan> <membid>`); without it the
                // ircd rejects the whole link with "Insufficient parameters". The
                // trailing "1 o" is the 4-param form (ts, status modes): the bot
                // joins opped, matching Anope's default bot modes (+o). ts 1 keeps
                // it below the channel TS so the op is always applied.
                self.membid += 1;
                vec![format!(":{} IJOIN {} {} 1 o", uid, channel, self.membid)]
            }
            NetAction::ServicePart { uid, channel } => vec![format!(":{} PART {}", uid, channel)],
            // ENCAP the target's server: CHGHOST <uid> <newhost>, to set a vhost.
            NetAction::SetHost { uid, host } => {
                let target = uid.get(..3).unwrap_or(uid.as_str());
                vec![self.sourced(format!("ENCAP {} CHGHOST {} {}", target, uid, host))]
            }
            NetAction::SetIdent { uid, ident } => {
                let target = uid.get(..3).unwrap_or(uid.as_str());
                vec![self.sourced(format!("ENCAP {} CHGIDENT {} {}", target, uid, ident))]
            }
            NetAction::ForceNick { uid, nick } => {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(self.ts);
                vec![self.sourced(format!("SVSNICK {} {} {}", uid, nick, now))]
            }
            // SVSJOIN <uid> <chan> [key]: force a user into a channel, sourced from
            // the services server. Used to apply an account's auto-join list.
            // SVSPART <uid> <chan> [:reason]: force a user out of a channel.
            NetAction::ForcePart { uid, channel, reason } => {
                if reason.is_empty() {
                    vec![self.sourced(format!("SVSPART {} {}", uid, channel))]
                } else {
                    vec![self.sourced(format!("SVSPART {} {} :{}", uid, channel, reason))]
                }
            }
            NetAction::ForceJoin { uid, channel, key } => {
                if key.is_empty() {
                    vec![self.sourced(format!("SVSJOIN {} {}", uid, channel))]
                } else {
                    vec![self.sourced(format!("SVSJOIN {} {} {}", uid, channel, key))]
                }
            }
            // FMODE <chan> <ts> <modes>. The ircd drops an FMODE whose TS is newer
            // than the channel's, so we send TS 1 to guarantee it applies. Sourced
            // from the given pseudoclient (e.g. ChanServ) so users see who set it,
            // or from the services server when `from` is empty.
            NetAction::ChannelMode { from, channel, modes } => {
                let cmd = format!("FMODE {} 1 {}", channel, modes);
                if from.is_empty() {
                    vec![self.sourced(cmd)]
                } else {
                    vec![format!(":{} {}", from, cmd)]
                }
            }
            NetAction::Kick { from, channel, uid, reason } => {
                vec![format!(":{} KICK {} {} :{}", from, channel, uid, reason)]
            }
            // FTOPIC <chan> <chanTS> <topicTS> <setter> :<topic>. TS 1 so the ircd
            // always accepts it; sourced from the given pseudoclient.
            NetAction::Topic { from, channel, topic } => {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(self.ts);
                vec![format!(":{} FTOPIC {} 1 {} {} :{}", from, channel, now, from, topic)]
            }
            // INVITE <uid> <chan> <chanTS> <expiry>. Expiry 0 = no expiry.
            NetAction::Invite { from, uid, channel } => {
                vec![format!(":{} INVITE {} {} 1 0", from, uid, channel)]
            }
            // ADDLINE <type> <mask> <setter> <set-time> <duration> :<reason>. A
            // duration of 0 is permanent; the ircd applies it to matching users
            // already online and propagates it across the network.
            NetAction::AddLine { kind, mask, setter, duration, reason } => {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(self.ts);
                vec![self.sourced(format!("ADDLINE {} {} {} {} {} :{}", kind, mask, setter, now, duration, reason))]
            }
            NetAction::DelLine { kind, mask } => vec![self.sourced(format!("DELLINE {} {}", kind, mask))],
            NetAction::KillUser { from, uid, reason } => vec![format!(":{} KILL {} :{}", from, uid, reason)],
            // Introduce a server behind us: :<our-sid> SERVER <name> <sid> :<desc>.
            NetAction::JupeServer { name, sid, reason } => {
                vec![self.sourced(format!("SERVER {} {} :JUPED: {}", name, sid, reason))]
            }
            NetAction::Squit { target, reason } => vec![self.sourced(format!("SQUIT {} :{}", target, reason))],
            NetAction::Raw(s) => vec![s.clone()],
            // Internal: the link layer handles these before serialization.
            NetAction::DeferRegister { .. } | NetAction::DeferPassword { .. } | NetAction::DeferAuthenticate { .. } | NetAction::SendEmail { .. } | NetAction::Shutdown { .. } => vec![],
        };
        // A trailing parameter can carry free-form text (message bodies, kick
        // reasons, topics, metadata). Strip CR/LF/NUL at this single choke-point
        // so no such text — whatever its origin — can smuggle a second command
        // onto the s2s link.
        lines.into_iter().map(|l| l.replace(['\r', '\n', '\0'], "")).collect()
    }

    fn sid(&self) -> &str {
        &self.sid
    }
}

// Whether a channel mode consumes a parameter — the shared canonical arity, so
// parsing here and MODE-building in services never drift.
use echo_api::chanmode_takes_param as takes_param;

// Walk a mode change and its params for a key (+k/-k). Returns Some(Some(key))
// when a key is set, Some(None) when cleared, None when `k` isn't in the change.
fn scan_key(modes: &str, params: &[&str]) -> Option<Option<String>> {
    let mut adding = true;
    let mut pi = 0;
    let mut result = None;
    for m in modes.chars() {
        match m {
            '+' => adding = true,
            '-' => adding = false,
            'k' => {
                result = Some(if adding { params.get(pi).map(|s| s.to_string()) } else { None });
                pi += 1;
            }
            c if takes_param(c, adding) => pi += 1,
            _ => {}
        }
    }
    result
}

// Walk a mode change and its params for grants/revokes of one status mode
// (`want`, e.g. 'o' or 'v'). Returns (is_set, uid) per match, using the same
// param cursor as scan_key.
fn scan_status(modes: &str, params: &[&str], want: char) -> Vec<(bool, String)> {
    let mut adding = true;
    let mut pi = 0;
    let mut out = Vec::new();
    for m in modes.chars() {
        match m {
            '+' => adding = true,
            '-' => adding = false,
            c if c == want => {
                if let Some(p) = params.get(pi) {
                    out.push((adding, p.to_string()));
                }
                pi += 1;
            }
            c if takes_param(c, adding) => pi += 1,
            _ => {}
        }
    }
    out
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
        InspIrcd::new("services.test".into(), "Federated Services".into(), "42S".into(), "pw".into(), 1206, 1)
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

    // The ircd replaying `accountname` metadata (e.g. on our netburst) restores a
    // login; an empty value is a logout, and our own echoes and other keys are ignored.
    #[test]
    fn parses_accountname_metadata() {
        let mut p = proto();
        assert!(matches!(p.parse(":0IR METADATA 0IRAAAAAB accountname :alice").as_slice(),
            [NetEvent::AccountLogin { uid, account }] if uid == "0IRAAAAAB" && account == "alice"), "login restored");
        assert!(matches!(p.parse(":0IR METADATA 0IRAAAAAB accountname :").as_slice(),
            [NetEvent::AccountLogin { uid, account }] if uid == "0IRAAAAAB" && account.is_empty()), "empty value = logout");
        assert!(p.parse(":42S METADATA 0IRAAAAAB accountname :bob").is_empty(), "our own echo is ignored");
        assert!(p.parse(":0IR METADATA 0IRAAAAAB ssl_cert :deadbeef").is_empty(), "non-account keys ignored");
    }

    // A KILL surfaces as a UserKilled for the target uid.
    #[test]
    fn parses_kill() {
        let ev = proto().parse(":0IR KILL 0IRAAAAAB :bye now");
        assert!(matches!(ev.as_slice(), [NetEvent::UserKilled { uid }] if uid == "0IRAAAAAB"), "{ev:?}");
    }

    // The unsourced auth handshake registers our uplink; a sourced SERVER is a
    // downstream link tracked (with its parent) for the server tree.
    #[test]
    fn parses_server_link() {
        let mut p = proto();
        assert!(matches!(p.parse("SERVER hub.example password 0IR :a hub").as_slice(), [NetEvent::Registered]), "uplink handshake");
        assert!(matches!(p.parse(":0IR SERVER leaf.example 0XY :a leaf").as_slice(),
            [NetEvent::ServerLink { sid, parent }] if sid == "0XY" && parent == "0IR"), "downstream link");
    }

    // A SQUIT surfaces as a ServerSplit carrying the departed server's SID.
    #[test]
    fn parses_squit() {
        let ev = proto().parse(":42S SQUIT 0IR :ping timeout");
        assert!(matches!(ev.as_slice(), [NetEvent::ServerSplit { server }] if server == "0IR"), "{ev:?}");
    }

    // A UID burst introduces the user under their current nick.
    #[test]
    fn parses_uid_burst() {
        let ev = proto().parse(":0IR UID 0IRAAAAAB 1783833000 alice host host user user 0.0.0.0 1783833000 +i :real");
        assert!(
            matches!(ev.as_slice(), [NetEvent::UserConnect { uid, nick, .. }] if uid == "0IRAAAAAB" && nick == "alice"),
            "{ev:?}"
        );
    }

    // FJOIN (channel create/burst) surfaces as ChannelCreate for the channel, and
    // the member's uid is taken without its :membid suffix.
    #[test]
    fn parses_fjoin_as_channel_create() {
        let ev = proto().parse(":0IR FJOIN #chan 1783845132 +tn :o,0IRAAAAAB:0");
        assert!(matches!(ev.first(), Some(NetEvent::ChannelCreate { channel }) if channel == "#chan"), "{ev:?}");
        assert!(ev.iter().any(|e| matches!(e, NetEvent::Join { uid, .. } if uid == "0IRAAAAAB")), "{ev:?}");
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

    // FMODE and an FJOIN prefix both surface voice status changes.
    #[test]
    fn parses_voice_status() {
        // +o then +v with two params: op for the first uid, voice for the second.
        let ev = proto().parse(":0IRAAAAAB FMODE #chan 1783845132 +ov 0IRAAAAAB 0IRAAAAAC");
        assert!(ev.iter().any(|e| matches!(e, NetEvent::ChannelOp { uid, op: true, .. } if uid == "0IRAAAAAB")), "op: {ev:?}");
        assert!(ev.iter().any(|e| matches!(e, NetEvent::ChannelVoice { uid, voice: true, .. } if uid == "0IRAAAAAC")), "voice: {ev:?}");
        // A -v revokes voice.
        let ev = proto().parse(":0IRAAAAAB FMODE #chan 1783845132 -v 0IRAAAAAC");
        assert!(ev.iter().any(|e| matches!(e, NetEvent::ChannelVoice { uid, voice: false, .. } if uid == "0IRAAAAAC")), "devoice: {ev:?}");
        // A +v join prefix surfaces a voice event alongside the Join.
        let ev = proto().parse(":0IR FJOIN #chan 1783845132 +tn :v,0IRAAAAAD");
        assert!(ev.iter().any(|e| matches!(e, NetEvent::ChannelVoice { uid, voice: true, .. } if uid == "0IRAAAAAD")), "join voice: {ev:?}");
    }

    // A vhost is set by ENCAP'ing the target's own server with CHGHOST / CHGIDENT.
    #[test]
    fn serializes_set_host() {
        let lines = proto().serialize(&NetAction::SetHost { uid: "0IRAAAAAB".into(), host: "cool.example".into() });
        assert_eq!(lines, vec![":42S ENCAP 0IR CHGHOST 0IRAAAAAB cool.example".to_string()]);
        let lines = proto().serialize(&NetAction::SetIdent { uid: "0IRAAAAAB".into(), ident: "cool".into() });
        assert_eq!(lines, vec![":42S ENCAP 0IR CHGIDENT 0IRAAAAAB cool".to_string()]);
    }

    #[test]
    fn serializes_svspart() {
        let lines = proto().serialize(&NetAction::ForcePart { uid: "0IRAAAAAB".into(), channel: "#chan".into(), reason: "bye".into() });
        assert_eq!(lines, vec![":42S SVSPART 0IRAAAAAB #chan :bye".to_string()]);
        let lines = proto().serialize(&NetAction::ForcePart { uid: "0IRAAAAAB".into(), channel: "#chan".into(), reason: String::new() });
        assert_eq!(lines, vec![":42S SVSPART 0IRAAAAAB #chan".to_string()]);
    }

    // Free-form text with embedded line breaks must not smuggle a second line
    // onto the link: the serializer strips CR/LF/NUL from every outbound line.
    #[test]
    fn strips_crlf_from_trailing_text() {
        let lines = proto().serialize(&NetAction::Notice {
            from: "42SAAAAAA".into(),
            to: "0IRAAAAAB".into(),
            text: "hi\r\nKILL 0IRAAAAAB :pwned".into(),
        });
        assert_eq!(lines, vec![":42SAAAAAA NOTICE 0IRAAAAAB :hiKILL 0IRAAAAAB :pwned".to_string()]);
        assert!(!lines[0].contains('\n') && !lines[0].contains('\r'));
    }

    // Account-registration relay wire format, matching the ircd's account module:
    // a leaf forwards ENCAP <us> SWACCTREG <reqid> <origin> <kind> <account> <p2>
    // :<p3>, and we answer the origin server with ENCAP <origin> SWACCTRES. The
    // password is the trailing field so it may contain spaces.
    #[test]
    fn account_registration_relay_roundtrip() {
        let ev = proto().parse(":0IR ENCAP 42S SWACCTREG req1 0IR REGISTER neo neo@example.org :trinity pass");
        match ev.as_slice() {
            [NetEvent::AccountRequest { reqid, origin, kind, account, p2, p3 }] => {
                assert_eq!(reqid, "req1");
                assert_eq!(origin, "0IR");
                assert_eq!(kind, "REGISTER");
                assert_eq!(account, "neo");
                assert_eq!(p2, "neo@example.org");
                assert_eq!(p3, "trinity pass", "the password is trailing, spaces preserved");
            }
            other => panic!("expected one AccountRequest, got {other:?}"),
        }

        let lines = proto().serialize(&NetAction::AccountResponse {
            reqid: "req1".into(),
            origin: "0IR".into(),
            kind: "REGISTER".into(),
            account: "neo".into(),
            status: "verification_required".into(),
            code: "VERIFICATION_REQUIRED".into(),
            message: "check your email".into(),
        });
        assert_eq!(lines, vec![":42S ENCAP 0IR SWACCTRES req1 REGISTER neo verification_required VERIFICATION_REQUIRED :check your email".to_string()]);
    }

    // A network ban serializes to ADDLINE / DELLINE, sourced from our server.
    #[test]
    fn serializes_network_bans() {
        let add = proto().serialize(&NetAction::AddLine {
            kind: "G".into(),
            mask: "*@evil.host".into(),
            setter: "staff".into(),
            duration: 3600,
            reason: "spamming".into(),
        });
        assert_eq!(add.len(), 1);
        assert!(add[0].starts_with(":42S ADDLINE G *@evil.host staff "), "{add:?}");
        assert!(add[0].ends_with(" 3600 :spamming"), "{add:?}");
        let del = proto().serialize(&NetAction::DelLine { kind: "G".into(), mask: "*@evil.host".into() });
        assert_eq!(del, vec![":42S DELLINE G *@evil.host".to_string()]);
    }

    #[test]
    fn parses_ftopic_and_filters_own() {
        let ev = proto().parse(":0IRAAAAAB FTOPIC #chan 1783845132 1783845140 :Welcome all");
        assert!(
            matches!(ev.as_slice(), [NetEvent::TopicChange { channel, setter, topic }] if channel == "#chan" && setter == "0IRAAAAAB" && topic == "Welcome all"),
            "{ev:?}"
        );
        // The burst/RESYNC form carries a setby field before the topic.
        let ev = proto().parse(":0IRAAAAAB FTOPIC #chan 1783845132 1783845140 someone!u@h :Hi there");
        assert!(matches!(ev.as_slice(), [NetEvent::TopicChange { topic, .. }] if topic == "Hi there"), "{ev:?}");
        // Our own topic changes are filtered so enforcement can't loop.
        let ev = proto().parse(":42S FTOPIC #chan 1 1 :nope");
        assert!(!ev.iter().any(|e| matches!(e, NetEvent::TopicChange { .. })), "own change filtered: {ev:?}");
    }

    // FJOIN members and IJOIN both surface as Join events.
    #[test]
    fn parses_joins() {
        let ev = proto().parse(":0IR FJOIN #chan 1783845132 +nt :o,0IRAAAAAB ,0IRAAAAAC");
        assert!(matches!(ev.first(), Some(NetEvent::ChannelCreate { channel }) if channel == "#chan"));
        let joins: Vec<&str> = ev.iter().filter_map(|e| match e {
            NetEvent::Join { uid, .. } => Some(uid.as_str()),
            _ => None,
        }).collect();
        assert_eq!(joins, ["0IRAAAAAB", "0IRAAAAAC"]);

        // InspIRCd sends IJOIN with a membid (and optionally ts+modes) — tolerate it.
        let ev = proto().parse(":0IRAAAAAD IJOIN #chan 42");
        assert!(matches!(ev.as_slice(), [NetEvent::Join { uid, channel, op: false }] if uid == "0IRAAAAAD" && channel == "#chan"), "{ev:?}");
    }

    // Our own IJOIN must carry a membid, or the ircd rejects the link with
    // "Insufficient parameters" (the cutover crash on a bot-assigned channel).
    #[test]
    fn service_join_ijoin_includes_membid() {
        let mut p = proto();
        let a = p.serialize(&NetAction::ServiceJoin { uid: "00DB00000".into(), channel: "#taverne".into() });
        assert_eq!(a, vec![":00DB00000 IJOIN #taverne 1 1 o".to_string()], "joins opped with a membid");
        // membid is monotonic across joins
        let b = p.serialize(&NetAction::ServiceJoin { uid: "00DB00000".into(), channel: "#quizz".into() });
        assert_eq!(b, vec![":00DB00000 IJOIN #quizz 2 1 o".to_string()]);
    }
}
