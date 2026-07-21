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
    // User modes our pseudo-clients (services + bots) are introduced with, e.g.
    // "iHkBT" — invisible, hideoper, servprotect (U-line only), bot, block-CTCP.
    service_modes: String,
    // Monotonic membership id for our own IJOINs. InspIRCd requires a membid on
    // IJOIN (`IJOIN <chan> <membid>`); it need only be unique among our members.
    membid: u64,
    // Channel-mode arities learned from CAPAB CHANMODES. FMODE/FJOIN param scanning
    // consults this so a param-taking mode outside the static fallback table (e.g.
    // m_chanfilter's +g) doesn't desync the param cursor and mispair status/key args.
    chanmodes: std::collections::HashMap<char, echo_api::ChanModeCap>,
    // Whether the uplink loaded m_ircv3_ctctags (learned from CAPAB MODULES). Only
    // then can it relay the client-only `+` tags we attach to replies; otherwise we
    // emit the reply untagged.
    supports_ctctags: bool,
}

impl InspIrcd {
    pub fn new(name: String, description: String, sid: String, password: String, protocol: u32, ts: u64, service_modes: String) -> Self {
        Self { sid, name, description, password, protocol, ts, service_modes, membid: 0, chanmodes: std::collections::HashMap::new(), supports_ctctags: false }
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
        // Split off an optional IRCv3 message-tag prefix (@k=v;… ) — insp tags
        // PRIVMSGs with time/msgid, and it sits before the :source. We keep the
        // msgid to thread onto our replies (+draft/reply); the rest is parsed as-is.
        let (tag_prefix, line) = match line.strip_prefix('@') {
            Some(rest) => rest.split_once(' ').unwrap_or((rest, "")),
            None => ("", line),
        };
        let msgid = tag_prefix.split(';').find_map(|kv| kv.strip_prefix("msgid=")).map(str::to_string);
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
                // Downstream link: :<parent> SERVER <name> <sid> [hops] :<desc>.
                Some(parent) => {
                    let name = tokens.next().unwrap_or("").to_string();
                    match tokens.next() {
                        Some(sid) if !sid.is_empty() => vec![
                            NetEvent::ServerLink { sid: sid.to_string(), parent },
                            NetEvent::ServerInfo { sid: sid.to_string(), name },
                        ],
                        _ => vec![],
                    }
                }
                // Uplink auth handshake: SERVER <name> <password> <sid> :<desc>.
                None => {
                    let name = tokens.next().unwrap_or("").to_string();
                    let sid = tokens.nth(1).unwrap_or("").to_string(); // skip <password>
                    let mut out = vec![NetEvent::Registered];
                    if !sid.is_empty() {
                        out.push(NetEvent::ServerInfo { sid, name });
                    }
                    out
                }
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
            "IDLE" => {
                // `:<requester> IDLE <target>` — the idle half of a routed WHOIS.
                // Multi-param IDLE is a reply (never sent to us); ignore it.
                let target = tokens.next().unwrap_or("").to_string();
                match source {
                    Some(requester) if !target.is_empty() && tokens.next().is_none() => {
                        vec![NetEvent::Idle { requester, target }]
                    }
                    _ => vec![],
                }
            }
            // PRIVMSG and SQUERY both deliver a message to a service. SQUERY (the
            // form the NS/CS/… aliases use) is a 1206 command routed unicast to the
            // services server; since we advertise 1206 the ircd sends it raw rather
            // than folding it to PRIVMSG, so we must treat it the same.
            "PRIVMSG" | "SQUERY" => {
                let to = tokens.next().unwrap_or("").to_string();
                vec![NetEvent::Privmsg {
                    from: source.unwrap_or_default(),
                    to,
                    text: trailing(rest),
                    msgid,
                }]
            }
            // UID <uuid> <nickts> <nick> … — track who's online so services can
            // resolve a sender's current nick.
            // UID <uuid> <nickts> <nick> <realhost> <disphost> <realuser> <dispuser>
            // <ip> <signon> … — take the displayed host for ban masks and the ip
            // (index 7) for session limiting.
            "UID" => {
                // insp4: uuid nickts nick realhost disphost realuser dispuser ip signonts +modes[ params] :gecos
                let a: Vec<&str> = tokens.collect();
                match (a.first(), a.get(2)) {
                    (Some(uid), Some(nick)) => {
                        let realhost = a.get(3).unwrap_or(&"").to_string();
                        let host = a.get(4).unwrap_or(&"").to_string();
                        let ident = a.get(6).unwrap_or(&"").to_string();
                        let ip = a.get(7).unwrap_or(&"").to_string();
                        // gecos is the trailing param (has spaces) — take it whole.
                        let gecos = rest.split_once(" :").map_or("", |(_, g)| g).to_string();
                        vec![
                            NetEvent::UserConnect { uid: uid.to_string(), nick: nick.to_string(), host, ip },
                            NetEvent::UserAttrs { uid: uid.to_string(), ident, realhost, gecos },
                        ]
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
                        if let Some(key) = scan_key(modes, head.get(4..).unwrap_or(&[]), &self.chanmodes) {
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
                    vec![NetEvent::Part { uid: uid.to_string(), channel: chan.to_string(), reason: reason(rest) }]
                }
                _ => vec![],
            },
            // :<src> KICK <chan> <uid> :<reason> — a user removed from a channel.
            "KICK" => {
                let chan = tokens.next().unwrap_or("");
                match tokens.next() {
                    Some(uid) if chan.starts_with('#') => {
                        vec![NetEvent::Kicked { channel: chan.to_string(), uid: uid.to_string(), by: source.unwrap_or_default(), reason: reason(rest) }]
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
                        let mut out = vec![NetEvent::ChannelModeChange { channel: chan.to_string(), modes: modes.to_string(), setter: src.to_string() }];
                        if let Some(key) = scan_key(modes, params, &self.chanmodes) {
                            out.push(NetEvent::ChannelKey { channel: chan.to_string(), key });
                        }
                        for (op, uid) in scan_status(modes, params, 'o', &self.chanmodes) {
                            out.push(NetEvent::ChannelOp { channel: chan.to_string(), uid, op });
                        }
                        for (voice, uid) in scan_status(modes, params, 'v', &self.chanmodes) {
                            out.push(NetEvent::ChannelVoice { channel: chan.to_string(), uid, voice });
                        }
                        out
                    }
                    _ => vec![],
                }
            }
            // :<uid> MODE <target> <modes> — a user's own mode change (channel modes
            // arrive as FMODE). Skip our own pseudo-clients and any channel target.
            "MODE" => {
                let a: Vec<&str> = tokens.collect();
                match (source.as_deref(), a.first()) {
                    (Some(src), Some(target)) if !src.starts_with(self.sid.as_str()) && !target.starts_with('#') => {
                        let modes = a.get(1..).unwrap_or(&[]).join(" ");
                        if modes.is_empty() {
                            vec![]
                        } else {
                            vec![NetEvent::UserMode { uid: (*target).to_string(), modes }]
                        }
                    }
                    _ => vec![],
                }
            }
            // :<uid> OPERTYPE :<type> — a user opered up. Skip our own services.
            "OPERTYPE" => match source.as_deref() {
                Some(src) if !src.starts_with(self.sid.as_str()) => {
                    vec![NetEvent::OperUp { uid: src.to_string(), oper_type: trailing(rest) }]
                }
                _ => vec![],
            },
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
            // state. `accountname` (e.g. replayed on our netburst) restores who is
            // logged in (empty = logout); `ssl_cert` carries the TLS fingerprint for
            // the `fingerprint` extban.
            "METADATA" => {
                let a: Vec<&str> = tokens.collect();
                match (source.as_deref(), a.first(), a.get(1)) {
                    (Some(src), Some(target), Some(key)) if !src.starts_with(self.sid.as_str()) && *target != "*" => {
                        if key.eq_ignore_ascii_case("accountname") {
                            vec![NetEvent::AccountLogin { uid: target.to_string(), account: trailing(rest) }]
                        } else if key.eq_ignore_ascii_case("ssl_cert") {
                            // Value is "<flags> <fp,fp> <dn> <issuer>", or "<flags> <error>"
                            // when the flags contain 'E'. Take the first fingerprint.
                            let value = trailing(rest);
                            let mut parts = value.split_whitespace();
                            let flags = parts.next().unwrap_or("");
                            let fp = if flags.contains('E') { "" } else { parts.next().unwrap_or("").split(',').next().unwrap_or("") };
                            vec![NetEvent::UserCert { uid: target.to_string(), fp: fp.to_string() }]
                        } else {
                            vec![]
                        }
                    }
                    _ => vec![],
                }
            }
            "QUIT" => vec![NetEvent::Quit { uid: source.unwrap_or_default(), reason: reason(rest) }],
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
            // CAPAB EXTBANS :matching:account=R acting:mute=m … — the ircd's live
            // extban / channel-mode sets. Other CAPAB subcommands are noise.
            "CAPAB" => match tokens.next() {
                Some(s) if s.eq_ignore_ascii_case("EXTBANS") => {
                    let entries: Vec<_> = trailing(rest).split_whitespace().filter_map(parse_extban_cap).collect();
                    if entries.is_empty() {
                        vec![]
                    } else {
                        vec![NetEvent::ExtbanRegistry { entries }]
                    }
                }
                Some(s) if s.eq_ignore_ascii_case("CHANMODES") => {
                    let modes: Vec<_> = trailing(rest).split_whitespace().filter_map(parse_chanmode_cap).collect();
                    if modes.is_empty() {
                        vec![]
                    } else {
                        // Retain the arities locally too, for FMODE/FJOIN param scanning.
                        self.chanmodes = modes.iter().map(|m| (m.letter, *m)).collect();
                        vec![NetEvent::ChanModeRegistry { modes }]
                    }
                }
                // CAPAB CAPABILITIES :K=V … — a KV list; we care about CASEMAPPING.
                Some(s) if s.eq_ignore_ascii_case("CAPABILITIES") => {
                    match rest.split_whitespace().find_map(|t| t.trim_start_matches(':').strip_prefix("CASEMAPPING=")) {
                        Some(name) => vec![NetEvent::Casemapping { name: name.to_string() }],
                        None => vec![],
                    }
                }
                // CAPAB MODULES/MODSUPPORT :mod mod=data … — the ircd's loaded modules,
                // which echo verifies its dependencies against.
                Some(s) if s.eq_ignore_ascii_case("MODULES") || s.eq_ignore_ascii_case("MODSUPPORT") => {
                    let modules: Vec<_> = trailing(rest).split_whitespace().map(module_name).collect();
                    if modules.iter().any(|m| m == "ircv3_ctctags") {
                        self.supports_ctctags = true;
                    }
                    if modules.is_empty() {
                        vec![]
                    } else {
                        vec![NetEvent::ModulesAvailable { modules }]
                    }
                }
                // CAPAB USERMODES: we only need servprotect (+k) — verify our own
                // pseudoclients request it, so they can't be killed by operators.
                Some(s) if s.eq_ignore_ascii_case("USERMODES") => {
                    match trailing(rest).split_whitespace().find_map(servprotect_letter) {
                        Some(letter) => vec![NetEvent::ServProtect { letter, requested: self.service_modes.contains(letter) }],
                        None => vec![],
                    }
                }
                Some(s) if s.eq_ignore_ascii_case("END") => vec![NetEvent::CapabEnd],
                _ => vec![],
            },
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
            // Reply to a routed-WHOIS idle request, sourced from the target client:
            // `:<target> IDLE <requester> <signon> <idle>` (m_spanningtree/idle.cpp).
            NetAction::IdleReply { target, requester, signon, idle } => {
                vec![format!(":{target} IDLE {requester} {signon} {idle}")]
            }
            // Oper up a pseudo-client (legacy form, no privilege tags = full access;
            // the type name is what WHOIS shows: "is a <oper_type>").
            NetAction::OperType { uid, oper_type } => {
                vec![format!(":{uid} OPERTYPE :{oper_type}")]
            }
            // insp4 UID: uuid nickts nick realhost disphost realuser dispuser ip signonts +modes :gecos
            // (both a real AND a displayed user field — see m_spanningtree/uid.cpp Builder).
            NetAction::IntroduceUser { uid, nick, ident, host, gecos } => vec![self.sourced(format!(
                "UID {uid} {ts} {nick} {host} {host} {ident} {ident} 0.0.0.0 {ts} +{modes} :{gecos}",
                uid = uid, ts = self.ts, nick = nick, host = host, ident = ident, modes = self.service_modes, gecos = gecos
            ))],
            NetAction::Privmsg { from, to, text } => {
                split_body(text).into_iter().map(|chunk| format!(":{} PRIVMSG {} :{}", from, to, chunk)).collect()
            }
            NetAction::Notice { from, to, text } => {
                split_body(text).into_iter().map(|chunk| format!(":{} NOTICE {} :{}", from, to, chunk)).collect()
            }
            // Prepend the client tags to each line of the wrapped action — but only
            // if the uplink can relay them; otherwise emit the inner action untagged.
            NetAction::Tagged { tags, inner } => {
                let inner_lines = self.serialize(inner);
                if !self.supports_ctctags || tags.is_empty() {
                    inner_lines
                } else {
                    let prefix = tags.iter()
                        .map(|(k, v)| format!("{}={}", k, escape_tag_value(v)))
                        .collect::<Vec<_>>()
                        .join(";");
                    inner_lines.into_iter().map(|l| format!("@{} {}", prefix, l)).collect()
                }
            }
            // Standard reply: encapsulate for the target's server to re-emit locally
            // (FAIL/WARN/NOTE aren't s2s-routable). ENCAP * so only the server the
            // target is local to acts. "*" = no source service / no command.
            NetAction::StandardReply { kind, from, to, command, code, text } => {
                let src = if from.is_empty() { "*" } else { from.as_str() };
                let cmd = if command.is_empty() { "*" } else { command.as_str() };
                vec![self.sourced(format!(
                    "ENCAP * SWSTDRPL {to} {src} {verb} {cmd} {code} :{text}",
                    verb = kind.verb()
                ))]
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
            NetAction::ServiceJoin { uid, channel, modes } => {
                // IJOIN needs a membid (`IJOIN <chan> <membid>`); without it the
                // ircd rejects the whole link with "Insufficient parameters". The
                // trailing "1 <modes>" is the 4-param form (ts, status modes) — a
                // BotServ bot joins "+ao" (protected admin + op), core services "+o".
                // ts 1 keeps it below the channel TS so the status is always applied.
                self.membid += 1;
                vec![format!(":{} IJOIN {} {} 1 {}", uid, channel, self.membid, modes)]
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
            NetAction::Redact { from, target, msgid, reason } => vec![if reason.is_empty() {
                format!(":{from} REDACT {target} {msgid}")
            } else {
                format!(":{from} REDACT {target} {msgid} :{reason}")
            }],
            // Introduce a server behind us: :<our-sid> SERVER <name> <sid> :<desc>.
            NetAction::JupeServer { name, sid, reason } => {
                vec![self.sourced(format!("SERVER {} {} :JUPED: {}", name, sid, reason))]
            }
            NetAction::Squit { target, reason } => vec![self.sourced(format!("SQUIT {} :{}", target, reason))],
            NetAction::Raw(s) => vec![s.clone()],
            // Internal: the link layer handles these before serialization.
            NetAction::DeferRegister { .. } | NetAction::DeferPassword { .. } | NetAction::DeferAuthenticate { .. } | NetAction::DeferKeycard { .. } | NetAction::SendEmail { .. } | NetAction::DictLookup { .. } | NetAction::Shutdown { .. } | NetAction::Rehash { .. } => vec![],
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
fn scan_key(modes: &str, params: &[&str], learned: &std::collections::HashMap<char, echo_api::ChanModeCap>) -> Option<Option<String>> {
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
            c if arity(learned, c, adding) => pi += 1,
            _ => {}
        }
    }
    result
}

// Whether mode `c` consumes a param in this direction: the ircd's learned arity if
// we have it, else the static fallback table.
fn arity(learned: &std::collections::HashMap<char, echo_api::ChanModeCap>, c: char, adding: bool) -> bool {
    learned.get(&c).map(|cap| cap.takes_param(adding)).unwrap_or_else(|| takes_param(c, adding))
}

// Walk a mode change and its params for grants/revokes of one status mode
// (`want`, e.g. 'o' or 'v'). Returns (is_set, uid) per match, using the same
// param cursor as scan_key.
fn scan_status(modes: &str, params: &[&str], want: char, learned: &std::collections::HashMap<char, echo_api::ChanModeCap>) -> Vec<(bool, String)> {
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
            c if arity(learned, c, adding) => pi += 1,
            _ => {}
        }
    }
    out
}

// The IRC "trailing" argument: everything after the first " :", else the last word.
// Parse one `CAPAB EXTBANS` token — "<matching|acting>:<name>[=<letter>]" — into
// an ExtbanCap. Anything not shaped like that is skipped.
fn parse_extban_cap(token: &str) -> Option<echo_api::ExtbanCap> {
    let (ty, spec) = token.split_once(':')?;
    let acting = match ty {
        "acting" => true,
        "matching" => false,
        _ => return None,
    };
    let (name, letter) = match spec.split_once('=') {
        Some((n, l)) => (n, l.chars().next()),
        None => (spec, None),
    };
    (!name.is_empty()).then(|| echo_api::ExtbanCap { name: name.to_string(), letter, acting })
}

// The mode letter of the `servprotect` user mode in a CAPAB USERMODES token
// (`simple:servprotect=k`), or None for any other mode.
fn servprotect_letter(token: &str) -> Option<char> {
    let (_ty, spec) = token.split_once(':')?;
    let (name, val) = spec.split_once('=')?;
    if name.eq_ignore_ascii_case("servprotect") {
        val.chars().next()
    } else {
        None
    }
}

// Normalize a `CAPAB MODULES` token (`m_foo.so=data` / `foo=data` / `foo`) to the
// bare module name, matching the ircd's own naming.
fn module_name(token: &str) -> String {
    let name = token.split_once('=').map_or(token, |(n, _)| n);
    let name = name.strip_prefix("m_").unwrap_or(name);
    name.strip_suffix(".so").unwrap_or(name).to_string()
}

// Parse one `CAPAB CHANMODES` token into a ChanModeCap:
//   list:ban=b  param:key=k  param-set:limit=l  simple:moderated=m
//   prefix:<rank>:op=@o   (value is <symbol><letter>)
fn parse_chanmode_cap(token: &str) -> Option<echo_api::ChanModeCap> {
    use echo_api::ChanModeKind::*;
    let (ty, spec) = token.split_once(':')?;
    if ty == "prefix" {
        let (rank, rest) = spec.split_once(':')?;
        let (_name, val) = rest.split_once('=')?;
        let (symbol, letter) = (val.chars().next()?, val.chars().nth(1)?);
        return Some(echo_api::ChanModeCap { letter, kind: Prefix { symbol, rank: rank.parse().ok()? } });
    }
    let (_name, val) = spec.split_once('=')?;
    let letter = val.chars().next()?;
    let kind = match ty {
        "list" => List,
        "param" => ParamAlways,
        "param-set" => ParamSet,
        "simple" => Simple,
        _ => return None,
    };
    Some(echo_api::ChanModeCap { letter, kind })
}

fn trailing(rest: &str) -> String {
    match rest.find(" :") {
        Some(i) => rest[i + 2..].to_string(),
        None => rest.rsplit(' ').next().unwrap_or("").to_string(),
    }
}

// Escape a value for an IRCv3 message tag (the mandatory five substitutions), so
// a channel name or msgid carrying a space/semicolon can't break the tag list.
fn escape_tag_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            ';' => out.push_str("\\:"),
            ' ' => out.push_str("\\s"),
            '\\' => out.push_str("\\\\"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

// A free-text reason param (PART/KICK/QUIT), which the ircd always sends as a
// `:`-prefixed trailing. Unlike `trailing()`, a MISSING reason yields "" rather
// than the last preceding word — so `KICK #c target` (no reason) doesn't record
// the target uid as the reason.
fn reason(rest: &str) -> String {
    match rest.find(" :") {
        Some(i) => rest[i + 2..].to_string(),
        None => String::new(),
    }
}

// Message-body bytes kept per PRIVMSG/NOTICE line. The whole IRC line is 512
// bytes incl. CR-LF; leaving ~110 for the ircd-expanded `:nick!user@host CMD
// target :` prefix keeps even a max-length bot source under the limit, so the
// ircd never truncates a reply mid-word.
const MAX_MSG_TEXT: usize = 400;

// Split an over-long message body into `MAX_MSG_TEXT`-byte chunks, breaking on a
// char boundary (and preferably a space) so no NOTICE/PRIVMSG line is truncated.
// A CTCP body (contains 0x01) is never split — a split would strand its delimiter.
fn split_body(text: &str) -> Vec<&str> {
    if text.len() <= MAX_MSG_TEXT || text.contains('\x01') {
        return vec![text];
    }
    let mut out = Vec::new();
    let mut rest = text;
    while rest.len() > MAX_MSG_TEXT {
        let mut cut = MAX_MSG_TEXT;
        while cut > 0 && !rest.is_char_boundary(cut) {
            cut -= 1;
        }
        // Prefer to break at the last space in the back half of the window.
        if let Some(sp) = rest[..cut].rfind(' ') {
            if sp >= MAX_MSG_TEXT / 2 {
                cut = sp;
            }
        }
        if cut == 0 {
            // A single word longer than the window: hard-split at a char boundary.
            cut = rest.len().min(MAX_MSG_TEXT);
            while !rest.is_char_boundary(cut) {
                cut -= 1;
            }
        }
        let (head, tail) = rest.split_at(cut);
        out.push(head);
        rest = tail.trim_start_matches(' ');
    }
    if !rest.is_empty() {
        out.push(rest);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proto() -> InspIrcd {
        InspIrcd::new("services.test".into(), "Federated Services".into(), "42S".into(), "pw".into(), 1206, 1, "iHkBT".into())
    }

    // A KICK/PART/QUIT with no explicit `:reason` must record an EMPTY reason,
    // not the last preceding word (a channel/target token).
    #[test]
    fn kick_without_reason_is_empty_not_the_target() {
        let ev = proto().parse(":42SAAAAAB KICK #chan 0IRAAAAAB");
        assert!(
            matches!(ev.as_slice(), [NetEvent::Kicked { reason, .. }] if reason.is_empty()),
            "{ev:?}"
        );
        let ev = proto().parse(":42SAAAAAB KICK #chan 0IRAAAAAB :flooding");
        assert!(
            matches!(ev.as_slice(), [NetEvent::Kicked { reason, .. }] if reason == "flooding"),
            "{ev:?}"
        );
        let ev = proto().parse(":0IRAAAAAB QUIT");
        assert!(matches!(ev.as_slice(), [NetEvent::Quit { reason, .. }] if reason.is_empty()), "{ev:?}");
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
        assert!(p.parse(":0IR METADATA 0IRAAAAAB swhois :hi").is_empty(), "unhandled keys ignored");
    }

    // `ssl_cert` metadata surfaces the TLS fingerprint (2nd field) for the extban;
    // a cert error (flags contain 'E') has no fingerprint.
    #[test]
    fn parses_ssl_cert_metadata() {
        let mut p = proto();
        assert!(matches!(p.parse(":0IR METADATA 0IRAAAAAB ssl_cert :VTrSe aabbccddeeff /CN=user /CN=CA").as_slice(),
            [NetEvent::UserCert { uid, fp }] if uid == "0IRAAAAAB" && fp == "aabbccddeeff"), "fingerprint captured");
        assert!(matches!(p.parse(":0IR METADATA 0IRAAAAAB ssl_cert :vTrSE unable to get certificate").as_slice(),
            [NetEvent::UserCert { fp, .. }] if fp.is_empty()), "cert error = no fingerprint");
        assert!(p.parse(":42S METADATA 0IRAAAAAB ssl_cert :VTrSe aabbccdd").is_empty(), "our own echo is ignored");
    }

    // CAPAB EXTBANS surfaces the ircd's live extban set: name, optional letter,
    // and matching-vs-acting. Malformed tokens are skipped; other CAPAB lines don't.
    #[test]
    fn parses_capab_extbans() {
        let mut p = proto();
        let ev = p.parse("CAPAB EXTBANS :matching:account=R acting:mute=m matching:noletter garbage");
        let [NetEvent::ExtbanRegistry { entries }] = ev.as_slice() else { panic!("{ev:?}") };
        assert_eq!(entries.len(), 3, "garbage token skipped");
        assert_eq!(entries[0], echo_api::ExtbanCap { name: "account".into(), letter: Some('R'), acting: false });
        assert_eq!(entries[1], echo_api::ExtbanCap { name: "mute".into(), letter: Some('m'), acting: true });
        assert_eq!(entries[2], echo_api::ExtbanCap { name: "noletter".into(), letter: None, acting: false });
        assert!(p.parse("CAPAB CHANMODES :ban=b").is_empty(), "other CAPAB subcommands ignored");
    }

    // CAPAB USERMODES surfaces servprotect and whether our service_modes request it
    // (proto()'s service_modes includes k). Only servprotect is extracted.
    #[test]
    fn parses_capab_usermodes_servprotect() {
        let mut p = proto();
        assert!(matches!(p.parse("CAPAB USERMODES :simple:invisible=i simple:servprotect=k param:snomask=s").as_slice(),
            [NetEvent::ServProtect { letter: 'k', requested: true }]));
        assert!(matches!(p.parse("CAPAB USERMODES :simple:servprotect=Z").as_slice(),
            [NetEvent::ServProtect { letter: 'Z', requested: false }]), "char not in service_modes -> not requested");
        assert!(p.parse("CAPAB USERMODES :simple:invisible=i simple:wallops=w").is_empty(), "no servprotect -> nothing");
    }

    // CAPAB MODULES/MODSUPPORT surface normalized module names; CAPAB END triggers
    // the dependency check. Names are stripped of m_/.so/=data.
    #[test]
    fn parses_capab_modules_and_end() {
        let mut p = proto();
        let ev = p.parse("CAPAB MODULES :m_account.so=1.0 cban chghost=2 ircv3_ctctags");
        let [NetEvent::ModulesAvailable { modules }] = ev.as_slice() else { panic!("{ev:?}") };
        assert_eq!(modules, &["account", "cban", "chghost", "ircv3_ctctags"]);
        assert!(matches!(p.parse("CAPAB MODSUPPORT :rline services").as_slice(),
            [NetEvent::ModulesAvailable { modules }] if modules == &["rline", "services"]));
        assert!(matches!(p.parse("CAPAB END").as_slice(), [NetEvent::CapabEnd]));
    }

    // SQUERY (what the NS/CS aliases use on proto 1206) is delivered to a service
    // just like a PRIVMSG, so it must surface the same event.
    #[test]
    fn squery_is_handled_like_privmsg() {
        let mut p = proto();
        assert!(matches!(p.parse(":0IRAAAAAB SQUERY 42SAAAAAB :HELP").as_slice(),
            [NetEvent::Privmsg { from, to, text, .. }] if from == "0IRAAAAAB" && to == "42SAAAAAB" && text == "HELP"));
    }

    // CAPAB CAPABILITIES surfaces CASEMAPPING (echo verifies it's ascii).
    #[test]
    fn parses_capab_casemapping() {
        let mut p = proto();
        assert!(matches!(p.parse("CAPAB CAPABILITIES :NICKMAX=31 CASEMAPPING=ascii CHANMAX=65").as_slice(),
            [NetEvent::Casemapping { name }] if name == "ascii"));
        assert!(p.parse("CAPAB CAPABILITIES :NICKMAX=31 CHANMAX=65").is_empty(), "no CASEMAPPING token -> nothing");
    }

    // CAPAB CHANMODES surfaces mode arity + prefix modes, including a custom prefix
    // like ojoin's Y (symbol !, rank 9000000) that the hardcoded set doesn't know.
    #[test]
    fn parses_capab_chanmodes() {
        use echo_api::ChanModeKind::*;
        let mut p = proto();
        let ev = p.parse("CAPAB CHANMODES :list:ban=b param-set:limit=l param:key=k prefix:30000:op=@o prefix:9000000:official-join=!Y simple:moderated=m");
        let [NetEvent::ChanModeRegistry { modes }] = ev.as_slice() else { panic!("{ev:?}") };
        let find = |c: char| modes.iter().find(|m| m.letter == c).copied();
        assert_eq!(find('b').unwrap().kind, List);
        assert_eq!(find('l').unwrap().kind, ParamSet);
        assert_eq!(find('k').unwrap().kind, ParamAlways);
        assert_eq!(find('m').unwrap().kind, Simple);
        assert_eq!(find('o').unwrap().kind, Prefix { symbol: '@', rank: 30000 });
        assert_eq!(find('Y').unwrap().kind, Prefix { symbol: '!', rank: 9000000 }, "custom ojoin prefix");
        // Arity: limit takes a param only when set; the key both ways.
        assert!(find('l').unwrap().takes_param(true) && !find('l').unwrap().takes_param(false));
        assert!(find('k').unwrap().takes_param(true) && find('k').unwrap().takes_param(false));
        assert!(find('Y').unwrap().is_prefix());
    }

    // A param-taking mode learned from CHANMODES but absent from the static table
    // (m_chanfilter's +g) must not desync the FMODE param cursor: the +o that
    // follows must grant to the real uid, not the +g mask param.
    #[test]
    fn fmode_param_cursor_uses_learned_chanmodes() {
        let mut p = proto();
        p.parse("CAPAB CHANMODES :list:filter=g prefix:30000:op=@o param:key=k");
        let ev = p.parse(":0IR FMODE #chan 1783845132 +go badword 0IRAAAAAB");
        assert!(ev.iter().any(|e| matches!(e, NetEvent::ChannelOp { uid, op, .. } if uid == "0IRAAAAAB" && *op)), "op grants to the real uid: {ev:?}");
        assert!(!ev.iter().any(|e| matches!(e, NetEvent::ChannelOp { uid, .. } if uid == "badword")), "the +g mask isn't mistaken for a nick: {ev:?}");
    }

    // Both SERVER forms surface a ServerInfo (SID -> name) for the `server` extban:
    // the uplink handshake (name password sid) and a sourced downstream link (name sid).
    #[test]
    fn parses_server_names() {
        let mut p = proto();
        assert!(p.parse("SERVER hub.example.net linkpass 0IR :A hub").iter()
            .any(|e| matches!(e, NetEvent::ServerInfo { sid, name } if sid == "0IR" && name == "hub.example.net")), "uplink name");
        assert!(p.parse(":0IR SERVER leaf.example.net 0XY :A leaf").iter()
            .any(|e| matches!(e, NetEvent::ServerInfo { sid, name } if sid == "0XY" && name == "leaf.example.net")), "downstream name");
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
        assert!(matches!(p.parse("SERVER hub.example password 0IR :a hub").as_slice(),
            [NetEvent::Registered, NetEvent::ServerInfo { .. }]), "uplink handshake");
        assert!(matches!(p.parse(":0IR SERVER leaf.example 0XY :a leaf").as_slice(),
            [NetEvent::ServerLink { sid, parent }, NetEvent::ServerInfo { .. }] if sid == "0XY" && parent == "0IR"), "downstream link");
    }

    // A SQUIT surfaces as a ServerSplit carrying the departed server's SID.
    #[test]
    fn parses_squit() {
        let ev = proto().parse(":42S SQUIT 0IR :ping timeout");
        assert!(matches!(ev.as_slice(), [NetEvent::ServerSplit { server }] if server == "0IR"), "{ev:?}");
    }

    // A UID burst introduces the user and, alongside, the identity fields the
    // UID carries that UserConnect omits (ident, real host, gecos).
    #[test]
    fn parses_uid_burst() {
        let ev = proto().parse(":0IR UID 0IRAAAAAB 1783833000 alice real.host disp.host ruser duser 1.2.3.4 1783833000 +i :Real Name");
        assert!(
            matches!(ev.as_slice(), [
                NetEvent::UserConnect { uid, nick, host, ip },
                NetEvent::UserAttrs { ident, realhost, gecos, .. },
            ] if uid == "0IRAAAAAB" && nick == "alice" && host == "disp.host" && ip == "1.2.3.4"
                && ident == "duser" && realhost == "real.host" && gecos == "Real Name"),
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
            matches!(ev.as_slice(), [NetEvent::ChannelModeChange { channel, modes, .. }] if channel == "#chan" && modes == "+m"),
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
    fn serializes_redact() {
        let with = proto().serialize(&NetAction::Redact { from: "42SAAAAAA".into(), target: "#c".into(), msgid: "abc".into(), reason: "spam".into() });
        assert_eq!(with, vec![":42SAAAAAA REDACT #c abc :spam".to_string()]);
        let without = proto().serialize(&NetAction::Redact { from: "42SAAAAAA".into(), target: "alice".into(), msgid: "xyz".into(), reason: String::new() });
        assert_eq!(without, vec![":42SAAAAAA REDACT alice xyz".to_string()], "no trailing when reason is empty");
    }

    // A tagged reply carries its `+draft/…` tags only after the uplink advertises
    // m_ircv3_ctctags; before that (or with no tags) it's emitted plain.
    #[test]
    fn serializes_tagged_notice_only_when_ctctags_loaded() {
        let tagged = || NetAction::Tagged {
            tags: vec![("+draft/reply".to_string(), "abc123".to_string())],
            inner: Box::new(NetAction::Notice { from: "42SAAAAAA".into(), to: "0IRAAAAAB".into(), text: "hi".into() }),
        };
        // No ctctags module -> tags dropped, plain notice.
        assert_eq!(proto().serialize(&tagged()), vec![":42SAAAAAA NOTICE 0IRAAAAAB :hi".to_string()]);
        // After CAPAB MODULES lists it -> the tag is prepended.
        let mut p = proto();
        p.parse("CAPAB MODULES :account ircv3_ctctags");
        assert_eq!(p.serialize(&tagged()), vec!["@+draft/reply=abc123 :42SAAAAAA NOTICE 0IRAAAAAB :hi".to_string()]);
    }

    // Tag values with reserved characters are escaped, and every split line of a
    // multi-line inner action carries the tags.
    #[test]
    fn tagged_values_escaped_and_applied_per_line() {
        let mut p = proto();
        p.parse("CAPAB MODULES :ircv3_ctctags");
        let out = p.serialize(&NetAction::Tagged {
            tags: vec![("+draft/channel-context".to_string(), "#a b".to_string())],
            inner: Box::new(NetAction::Notice { from: "42SAAAAAA".into(), to: "0IRAAAAAB".into(), text: "word ".repeat(200).trim().to_string() }),
        });
        assert!(out.len() >= 2, "long notice split into multiple lines");
        assert!(out.iter().all(|l| l.starts_with("@+draft/channel-context=#a\\sb :")), "every line tagged + escaped: {out:?}");
    }

    // insp tags an incoming PRIVMSG with a msgid; we capture it so the reply can
    // thread against it.
    #[test]
    fn parses_msgid_from_privmsg_tags() {
        let ev = proto().parse("@msgid=xyz789;time=2026-01-01T00:00:00Z :0IRAAAAAB PRIVMSG 42SAAAAAB :HELP");
        assert!(matches!(ev.as_slice(),
            [NetEvent::Privmsg { msgid: Some(m), text, .. }] if m == "xyz789" && text == "HELP"));
        // No tag prefix -> no msgid.
        let ev = proto().parse(":0IRAAAAAB PRIVMSG 42SAAAAAB :HELP");
        assert!(matches!(ev.as_slice(), [NetEvent::Privmsg { msgid: None, .. }]));
    }

    #[test]
    fn serializes_svspart() {
        let lines = proto().serialize(&NetAction::ForcePart { uid: "0IRAAAAAB".into(), channel: "#chan".into(), reason: "bye".into() });
        assert_eq!(lines, vec![":42S SVSPART 0IRAAAAAB #chan :bye".to_string()]);
        let lines = proto().serialize(&NetAction::ForcePart { uid: "0IRAAAAAB".into(), channel: "#chan".into(), reason: String::new() });
        assert_eq!(lines, vec![":42S SVSPART 0IRAAAAAB #chan".to_string()]);
    }

    #[test]
    fn long_notice_splits_under_the_line_limit() {
        let text = "word ".repeat(200).trim().to_string(); // 200 words, ~999 bytes
        let lines = proto().serialize(&NetAction::Notice { from: "42SAAAAAA".into(), to: "0IRAAAAAB".into(), text });
        assert!(lines.len() >= 3, "split into multiple lines, got {}", lines.len());
        let mut words = 0;
        for l in &lines {
            assert!(l.len() <= 512, "each line under 512 bytes: {}", l.len());
            let body = l.split_once(" :").expect("has a trailing param").1;
            words += body.split_whitespace().count();
        }
        assert_eq!(words, 200, "every word preserved across the split");
    }

    #[test]
    fn ctcp_body_is_never_split() {
        let text = format!("\x01{}\x01", "A".repeat(700));
        let lines = proto().serialize(&NetAction::Notice { from: "42SAAAAAA".into(), to: "0IRAAAAAB".into(), text });
        assert_eq!(lines.len(), 1, "a CTCP body stays on one line (a split would strand its \\x01)");
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

    // A standard reply encapsulates as ENCAP * SWSTDRPL <target> <source> <verb>
    // <command> <code> :<text>, sourced from the services server so the target's
    // server (m_services_stdrpl) can re-emit it locally.
    #[test]
    fn standard_reply_serializes_to_encap() {
        let lines = proto().serialize(&NetAction::StandardReply {
            kind: echo_api::ReplyKind::Fail,
            from: "42SAAAAAB".into(),
            to: "0IRAAAAAB".into(),
            command: "IDENTIFY".into(),
            code: "INVALID_CREDENTIALS".into(),
            text: "Invalid password. Please try again.".into(),
        });
        assert_eq!(lines, vec![":42S ENCAP * SWSTDRPL 0IRAAAAAB 42SAAAAAB FAIL IDENTIFY INVALID_CREDENTIALS :Invalid password. Please try again.".to_string()]);

        // Empty source/command collapse to "*".
        let lines = proto().serialize(&NetAction::StandardReply {
            kind: echo_api::ReplyKind::Note,
            from: String::new(),
            to: "0IRAAAAAB".into(),
            command: String::new(),
            code: "INFO".into(),
            text: "heads up".into(),
        });
        assert_eq!(lines, vec![":42S ENCAP * SWSTDRPL 0IRAAAAAB * NOTE * INFO :heads up".to_string()]);
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
        let a = p.serialize(&NetAction::ServiceJoin { uid: "00DB00000".into(), channel: "#taverne".into(), modes: "ao".into() });
        assert_eq!(a, vec![":00DB00000 IJOIN #taverne 1 1 ao".to_string()], "bot joins +ao (protected admin + op) with a membid");
        // membid is monotonic across joins; core services join +o
        let b = p.serialize(&NetAction::ServiceJoin { uid: "00DB00000".into(), channel: "#quizz".into(), modes: "o".into() });
        assert_eq!(b, vec![":00DB00000 IJOIN #quizz 2 1 o".to_string()]);
    }
}
