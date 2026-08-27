use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

// The read-only network view a module sees; re-exported so the engine keeps
// naming it locally.
pub use echo_api::{ChanSeenView, HelpEntry, IncidentView, NetView, Privs, SeenView};

// The most recent moderation/action incidents kept for LOGSEARCH.
const INCIDENT_CAP: usize = 10_000;

// Bound on the global last-seen map, so nick churn can't grow it without limit.
// Best-effort data: when it overflows, the stalest quarter is pruned.
const SEEN_CAP: usize = 20_000;

// Live network view, rebuilt from the uplink's burst each connect (ephemeral —
// unlike the account store, which persists).
#[derive(Default)]
pub struct Network {
    pub users: HashMap<String, User>, // keyed by UID
    channels: HashMap<String, Channel>, // keyed by lowercase name
    accounts: HashMap<String, String>, // UID -> logged-in account, until logout/quit
    seen: HashMap<String, Seen>,       // lowercase nick -> last activity
    // Our own service bots (lowercase nick -> live uid). Kept separate from
    // `users` so a reconnect can clear them wholesale without disturbing the
    // uplink-sourced user map.
    bots: HashMap<String, String>,
    // Downstream server tree: SID -> the SID that introduced it. Lets a hub's
    // SQUIT cascade to every server (and user) behind it. Rebuilt each link.
    servers: HashMap<String, String>,
    // SID -> server name, for the `server` extban. Rebuilt each link.
    server_names: HashMap<String, String>,
    // Module names the ircd advertised in its CAPAB burst. Rebuilt each link, used
    // to verify echo's dependencies at CAPAB END.
    ircd_modules: std::collections::HashSet<String>,
    // Shared, namespaced stat counters any service contributes to (persisted via
    // StatsSet). Read by StatServ and the gRPC Stats API.
    stats: BTreeMap<String, u64>,
    // Per-channel BOTSTATS activity (lines + top talkers), name-keyed and
    // persisted alongside `stats` so it survives a restart.
    chan_activity: HashMap<String, ChanActivity>,
    // Per-channel per-nick last message + time, for the channel-scoped SEEN.
    // Ephemeral (built from activity since services started), bounded per channel.
    chan_seen: HashMap<String, HashMap<String, ChanSeen>>,
    // Live session count per connecting IP, for OperServ session limiting.
    sessions: HashMap<String, u32>,
    // Recent moderation/action incidents (bounded ring), for OperServ LOGSEARCH.
    incidents: VecDeque<Incident>,
    incident_seq: u64,
    // ChanFix op-time scores: channel (lowercase) -> identity (account or host) ->
    // score. Sampled from live op state; ephemeral (node-local, rebuilt over time).
    chanfix: HashMap<String, HashMap<String, u32>>,
    // Network-wide help index (service nick, blurb, per-command topics), built by
    // the engine at startup from every service so HelpServ can front it.
    pub help_catalog: Vec<(String, &'static str, &'static [HelpEntry])>,
    // The declarative config operators and the privilege tier each holds, mirrored
    // from the engine so services can enumerate staff (MemoServ STAFF) and show a
    // role (NickServ INFO). Runtime OPER grants live in the store; a caller unions
    // the two.
    config_opers: HashMap<String, Privs>,
}

// ChanFix scoring caps and rates.
const CHANFIX_MAX: u32 = 5000;
const CHANFIX_BUMP: u32 = 2; // per sample while opped (net +1 after the -1 decay)

// One recorded action: a short id (also stamped into the action's reason), the
// unix time it happened, and a human summary.
struct Incident {
    id: String,
    ts: u64,
    summary: String,
}

// A short uppercase base-36 incident code from a monotonic counter.
fn incident_code(seq: u64) -> String {
    const C: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if seq == 0 {
        return "0".to_string();
    }
    let mut n = seq;
    let mut out = Vec::new();
    while n > 0 {
        out.push(C[(n % 36) as usize]);
        n /= 36;
    }
    out.reverse();
    String::from_utf8(out).unwrap()
}

pub struct User {
    pub uid: String,
    pub nick: String,
    pub ident: String,    // user@ — from the UID (was discarded); empty until UserAttrs
    pub host: String,     // the displayed host
    pub realhost: String, // the real host, for host bans against it
    pub ip: String,
    pub gecos: String,       // real name, for realname / realmask extbans
    pub fingerprint: String, // TLS cert fingerprint (ssl_cert metadata); empty = none
    pub oper: String,        // oper type from OperUp; empty = not an oper
    pub umodes: BTreeSet<char>, // live user modes, accumulated from UserMode deltas
}

// A channel's live membership, ops, and current key (+k), tracked from the burst.
#[derive(Default)]
pub struct Channel {
    pub members: HashSet<String>, // uids
    pub ops: HashSet<String>,     // uids holding channel-operator status
    pub voices: HashSet<String>,  // uids holding +v
    pub key: Option<String>,
    pub topic: String,            // live topic text
    pub topic_setter: String,     // who set it (nick!user@host mask)
    pub cmodes: BTreeSet<char>,   // simple channel-mode flags, from FMODE deltas
}

// Apply an IRC mode delta ("+nt-s", "+k key") to a flag set: letters after `+`
// are added, after `-` removed; anything from the first space (params) is ignored.
// `skip` names letters never recorded as flags (prefix/list modes for channels).
fn apply_mode_delta(set: &mut BTreeSet<char>, delta: &str, skip: &str) {
    let mut adding = true;
    for ch in delta.chars() {
        match ch {
            '+' => adding = true,
            '-' => adding = false,
            ' ' => break,
            c if c.is_ascii_alphabetic() && !skip.contains(c) => {
                if adding {
                    set.insert(c);
                } else {
                    set.remove(&c);
                }
            }
            _ => {}
        }
    }
}

// Per-channel BOTSTATS activity: total lines and per-nick counts (top talkers).
// Held name-keyed (not on the live Channel, which is rebuilt from each burst) and
// persisted, so a channel's history survives a services restart.
#[derive(Default, Clone)]
pub struct ChanActivity {
    pub lines: u64,
    pub talkers: HashMap<String, u64>,
}

// The last time a nick was seen, and doing what.
pub struct Seen {
    pub nick: String,
    pub ts: u64,
    pub what: String,
}

// A nick's last message in a channel, for the channel-scoped SEEN.
pub struct ChanSeen {
    pub nick: String,
    pub ts: u64,
    pub msg: String,
}

// Rich per-entity views for the web panel (owned snapshots taken under the lock).
pub struct NetUser {
    pub uid: String,
    pub nick: String,
    pub ident: String,
    pub host: String,
    pub ip: String,
    pub gecos: String,
    pub account: String,
    pub oper: String,
    pub modes: String,
    pub server: String,
    pub secure: bool,
}

pub struct NetChan {
    pub name: String,
    pub users: usize,
    pub topic: String,
    pub topic_setter: String,
    pub modes: String,
    pub keyed: bool,
    pub secret: bool,
    pub private: bool,
    pub moderated: bool,
    pub inviteonly: bool,
    pub registered: bool, // filled in by the engine (which holds the account/channel db)
}

pub struct NetSrv {
    pub name: String,
    pub users: usize,
    pub opers: usize,
    pub uplink: String,
}

pub struct NetMember {
    pub nick: String,
    pub prefix: &'static str, // "@", "+", or ""
    pub account: String,
    pub oper: bool,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn lc(s: &str) -> String {
    s.to_ascii_lowercase()
}

impl Network {
    pub fn user_connect(&mut self, uid: String, nick: String, host: String, ip: String) {
        if !ip.is_empty() {
            *self.sessions.entry(ip.clone()).or_insert(0) += 1;
        }
        self.users.insert(uid.clone(), User { uid, nick, ident: String::new(), host, realhost: String::new(), ip, gecos: String::new(), fingerprint: String::new(), oper: String::new(), umodes: BTreeSet::new() });
    }

    // Record a user's oper type (from OperUp); empty string clears it (deoper).
    pub fn set_user_oper(&mut self, uid: &str, oper_type: String) {
        if let Some(u) = self.users.get_mut(uid) {
            if oper_type.is_empty() {
                u.oper.clear();
                u.umodes.remove(&'o');
            } else {
                u.oper = oper_type;
                u.umodes.insert('o');
            }
        }
    }

    // Apply a user-mode delta to the live view; a `-o` also clears the oper type.
    pub fn apply_user_mode(&mut self, uid: &str, delta: &str) {
        if let Some(u) = self.users.get_mut(uid) {
            apply_mode_delta(&mut u.umodes, delta, "");
            if !u.umodes.contains(&'o') {
                u.oper.clear();
            }
        }
    }

    // Remember a channel's live topic and who set it.
    pub fn set_channel_topic(&mut self, channel: &str, topic: String, setter: String) {
        let c = self.channels.entry(lc(channel)).or_default();
        c.topic = topic;
        c.topic_setter = setter;
    }

    // Apply a channel-mode delta to the live flag set (skipping prefix/list modes).
    pub fn apply_channel_mode(&mut self, channel: &str, delta: &str) {
        let c = self.channels.entry(lc(channel)).or_default();
        apply_mode_delta(&mut c.cmodes, delta, "ovhaqbeI");
    }

    // Fill in the rest of a user's identity (ident, real host, real name), which
    // the UID carries but UserConnect doesn't — needed for extban matching.
    pub fn set_user_attrs(&mut self, uid: &str, ident: String, realhost: String, gecos: String) {
        if let Some(u) = self.users.get_mut(uid) {
            u.ident = ident;
            u.realhost = realhost;
            u.gecos = gecos;
        }
    }

    // Record a user's TLS fingerprint (ssl_cert metadata), for the `fingerprint` extban.
    pub fn set_user_cert(&mut self, uid: &str, fp: String) {
        if let Some(u) = self.users.get_mut(uid) {
            u.fingerprint = fp;
        }
    }

    // A user's TLS cert fingerprint, if they presented one on connect.
    pub fn fingerprint_of(&self, uid: &str) -> Option<&str> {
        self.users.get(uid).map(|u| u.fingerprint.as_str()).filter(|f| !f.is_empty())
    }

    // Record a server's name for its SID, so the `server` extban can resolve which
    // server a user is on (their uid's SID prefix).
    pub fn set_server_name(&mut self, sid: &str, name: String) {
        self.server_names.insert(sid.to_string(), name);
    }

    // Accumulate ircd module names from a CAPAB MODULES/MODSUPPORT line.
    pub fn learn_modules(&mut self, names: Vec<String>) {
        self.ircd_modules.extend(names);
    }

    // Whether the ircd advertised module `name`. Empty set (never received) reads
    // as unknown → callers should skip the dependency check.
    pub fn has_module(&self, name: &str) -> bool {
        self.ircd_modules.contains(name)
    }

    pub fn module_count(&self) -> usize {
        self.ircd_modules.len()
    }

    // Mirror the engine's declarative config operators, so services can enumerate
    // staff. Called whenever the config oper set changes.
    pub fn set_config_opers(&mut self, opers: HashMap<String, Privs>) {
        self.config_opers = opers;
    }

    // Live sessions from `ip`.
    pub fn session_count(&self, ip: &str) -> u32 {
        self.sessions.get(ip).copied().unwrap_or(0)
    }

    // IPs with at least `min` live sessions, most sessions first.
    pub fn sessions_over(&self, min: u32) -> Vec<(String, u32)> {
        let mut v: Vec<(String, u32)> = self.sessions.iter().filter(|(_, &n)| n >= min).map(|(ip, &n)| (ip.clone(), n)).collect();
        v.sort_by_key(|&(_, n)| std::cmp::Reverse(n));
        v
    }

    // Record an action in the incident log and return its short id (to stamp into
    // the action's reason). The ring is bounded, dropping the oldest.
    pub fn record_incident(&mut self, summary: String, now: u64) -> String {
        let id = incident_code(self.incident_seq);
        self.incident_seq += 1;
        self.incidents.push_back(Incident { id: id.clone(), ts: now, summary });
        while self.incidents.len() > INCIDENT_CAP {
            self.incidents.pop_front();
        }
        id
    }

    // Incidents matching `pattern` (id-exact or summary-substring, case-
    // insensitive; empty = all), newest first, capped at `limit`.
    pub fn search_incidents(&self, pattern: &str, limit: usize) -> Vec<IncidentView> {
        let p = pattern.to_ascii_lowercase();
        self.incidents
            .iter()
            .rev()
            .filter(|i| p.is_empty() || i.id.eq_ignore_ascii_case(&p) || i.summary.to_ascii_lowercase().contains(&p))
            .take(limit)
            .map(|i| IncidentView { id: i.id.clone(), ts: i.ts, summary: i.summary.clone() })
            .collect()
    }

    // Resolve a nick to its uid (case-insensitive). Checks real users first,
    // then our own service bots.
    pub fn uid_by_nick(&self, nick: &str) -> Option<&str> {
        self.users
            .values()
            .find(|u| u.nick.eq_ignore_ascii_case(nick))
            .map(|u| u.uid.as_str())
            .or_else(|| self.bots.get(&nick.to_ascii_lowercase()).map(String::as_str))
    }

    // Track / forget one of our service bots by lowercase nick.
    pub fn bot_connect(&mut self, nick: &str, uid: &str) {
        self.bots.insert(nick.to_ascii_lowercase(), uid.to_string());
    }

    pub fn bot_forget(&mut self, nick_lc: &str) {
        self.bots.remove(nick_lc);
    }

    pub fn clear_bots(&mut self) {
        self.bots.clear();
    }

    pub fn host_of(&self, uid: &str) -> Option<&str> {
        self.users.get(uid).map(|u| u.host.as_str())
    }

    pub fn ident_of(&self, uid: &str) -> Option<&str> {
        self.users.get(uid).map(|u| u.ident.as_str())
    }

    // A user's identity for extban / ban matching (nick, ident, hosts, ip, gecos,
    // account). `None` if we don't know the uid.
    pub fn ban_target<'a>(&'a self, uid: &str) -> Option<echo_api::BanTarget<'a>> {
        let u = self.users.get(uid)?;
        Some(echo_api::BanTarget {
            nick: &u.nick,
            ident: &u.ident,
            host: &u.host,
            realhost: &u.realhost,
            ip: &u.ip,
            gecos: &u.gecos,
            account: self.accounts.get(uid).map(String::as_str),
            // A uid's first 3 chars are its server's SID; resolve that to the name.
            server: uid.get(..3).and_then(|sid| self.server_names.get(sid)).map_or("", String::as_str),
            fingerprint: (!u.fingerprint.is_empty()).then_some(u.fingerprint.as_str()),
            channels: self.channels_of(uid),
        })
    }

    // A minimal identity snapshot for the anti-abuse detectors — (ip, nick!ident@host)
    // in a single lookup, skipping ban_target's channel-list allocation (these run on
    // every join/part/quit/nick, not just on connect).
    pub fn abuse_ident(&self, uid: &str) -> Option<(String, String)> {
        let u = self.users.get(uid)?;
        Some((u.ip.clone(), format!("{}!{}@{}", u.nick, u.ident, u.host)))
    }

    /// The channels `uid` is currently in (for the `channel` extban).
    pub fn channels_of(&self, uid: &str) -> Vec<String> {
        self.channels.iter().filter(|(_, c)| c.members.contains(uid)).map(|(k, _)| k.clone()).collect()
    }

    // Every known user whose uid carries `sid` as its prefix — i.e. those behind
    // a server, used to forget them all when it splits (SQUIT).
    pub fn uids_on_server(&self, sid: &str) -> Vec<String> {
        self.users.keys().filter(|u| u.starts_with(sid)).cloned().collect()
    }

    // --- read-only overview accessors for the web panel ---
    pub fn user_count(&self) -> usize {
        self.users.len()
    }
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }
    pub fn server_count(&self) -> usize {
        self.server_names.len()
    }
    /// Sorted names of the modules the ircd advertised in its CAPAB burst.
    pub fn module_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.ircd_modules.iter().cloned().collect();
        v.sort();
        v
    }

    /// Online opers (users with a non-empty oper type).
    pub fn oper_count(&self) -> usize {
        self.users.values().filter(|u| !u.oper.is_empty()).count()
    }

    fn to_netuser(&self, u: &User) -> NetUser {
        NetUser {
            uid: u.uid.clone(),
            nick: u.nick.clone(),
            ident: u.ident.clone(),
            host: u.host.clone(),
            ip: u.ip.clone(),
            gecos: u.gecos.clone(),
            account: self.accounts.get(&u.uid).cloned().unwrap_or_default(),
            oper: u.oper.clone(),
            modes: u.umodes.iter().collect(),
            server: u.uid.get(..3).and_then(|sid| self.server_names.get(sid)).cloned().unwrap_or_default(),
            secure: !u.fingerprint.is_empty(),
        }
    }

    /// Every online user, full detail, sorted by nick.
    pub fn users_detailed(&self) -> Vec<NetUser> {
        let mut v: Vec<NetUser> = self.users.values().map(|u| self.to_netuser(u)).collect();
        v.sort_by_key(|a| a.nick.to_lowercase());
        v
    }

    /// One online user by nick (case-insensitive), full detail.
    pub fn user_detail(&self, nick: &str) -> Option<NetUser> {
        self.users.values().find(|u| u.nick.eq_ignore_ascii_case(nick)).map(|u| self.to_netuser(u))
    }

    /// The channels a uid is in, each with the user's prefix ("@"/"+"/"").
    pub fn user_channels(&self, uid: &str) -> Vec<(String, &'static str)> {
        let mut v: Vec<(String, &'static str)> = self
            .channels
            .iter()
            .filter(|(_, c)| c.members.contains(uid))
            .map(|(name, c)| {
                let p = if c.ops.contains(uid) { "@" } else if c.voices.contains(uid) { "+" } else { "" };
                (name.clone(), p)
            })
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    /// Every live channel, full detail, largest first. `registered` is left false
    /// (the engine, which holds the channel db, fills it in).
    pub fn channels_detailed(&self) -> Vec<NetChan> {
        let mut v: Vec<NetChan> = self.channels.iter().map(|(name, c)| self.to_netchan(name, c)).collect();
        v.sort_by(|a, b| b.users.cmp(&a.users).then_with(|| a.name.cmp(&b.name)));
        v
    }

    /// One live channel by name (case-insensitive), full detail.
    pub fn channel_detail(&self, name: &str) -> Option<NetChan> {
        let key = lc(name);
        self.channels.get(&key).map(|c| self.to_netchan(&key, c))
    }

    /// The members of a channel with their prefix and account, ops first.
    pub fn channel_member_views(&self, name: &str) -> Vec<NetMember> {
        let Some(c) = self.channels.get(&lc(name)) else { return Vec::new() };
        let mut v: Vec<NetMember> = c
            .members
            .iter()
            .filter_map(|uid| {
                self.users.get(uid).map(|u| NetMember {
                    nick: u.nick.clone(),
                    prefix: if c.ops.contains(uid) { "@" } else if c.voices.contains(uid) { "+" } else { "" },
                    account: self.accounts.get(uid).cloned().unwrap_or_default(),
                    oper: !u.oper.is_empty(),
                })
            })
            .collect();
        // Ops first, then voice, then plain; alpha within each tier.
        v.sort_by(|a, b| {
            let rank = |p: &str| match p { "@" => 0, "+" => 1, _ => 2 };
            rank(a.prefix).cmp(&rank(b.prefix)).then_with(|| a.nick.to_lowercase().cmp(&b.nick.to_lowercase()))
        });
        v
    }

    fn to_netchan(&self, name: &str, c: &Channel) -> NetChan {
        NetChan {
            name: name.to_string(),
            users: c.members.len(),
            topic: c.topic.clone(),
            topic_setter: c.topic_setter.clone(),
            modes: c.cmodes.iter().collect(),
            keyed: c.key.is_some(),
            secret: c.cmodes.contains(&'s'),
            private: c.cmodes.contains(&'p'),
            moderated: c.cmodes.contains(&'m'),
            inviteonly: c.cmodes.contains(&'i'),
            registered: false,
        }
    }

    /// Linked servers, full detail (user + oper counts, uplink name).
    pub fn servers_detailed(&self) -> Vec<NetSrv> {
        let mut v: Vec<NetSrv> = self
            .server_names
            .iter()
            .map(|(sid, name)| {
                let uids = self.uids_on_server(sid);
                let opers = uids.iter().filter(|u| self.users.get(*u).is_some_and(|x| !x.oper.is_empty())).count();
                let uplink = self.servers.get(sid).and_then(|p| self.server_names.get(p)).cloned().unwrap_or_default();
                NetSrv { name: name.clone(), users: uids.len(), opers, uplink }
            })
            .collect();
        v.sort_by(|a, b| b.users.cmp(&a.users).then_with(|| a.name.cmp(&b.name)));
        v
    }

    // Record a downstream server and the SID that introduced it (its parent).
    pub fn server_link(&mut self, sid: &str, parent: &str) {
        self.servers.insert(sid.to_string(), parent.to_string());
    }

    // Forget the server subtree behind (and including) `sid` — its own SID plus
    // every server introduced beneath it — and return the whole set so their users
    // can be forgotten too. A hub's SQUIT arrives once but takes its children with it.
    pub fn server_split(&mut self, sid: &str) -> Vec<String> {
        let mut subtree = vec![sid.to_string()];
        let mut i = 0;
        while i < subtree.len() {
            let parent = subtree[i].clone();
            for (child, up) in &self.servers {
                if up == &parent && !subtree.contains(child) {
                    subtree.push(child.clone());
                }
            }
            i += 1;
        }
        for s in &subtree {
            self.servers.remove(s);
            self.server_names.remove(s);
        }
        subtree
    }

    // Drop the whole server tree (on a fresh link, before the burst rebuilds it).
    pub fn clear_servers(&mut self) {
        self.servers.clear();
        self.server_names.clear();
        self.ircd_modules.clear();
    }

    pub fn user_nick_change(&mut self, uid: &str, nick: String) {
        let Some(old) = self.users.get_mut(uid).map(|user| std::mem::replace(&mut user.nick, nick.clone())) else {
            return;
        };
        self.record_seen(lc(&nick), Seen { nick, ts: now(), what: format!("changing nick from {old}") });
    }

    pub fn user_quit(&mut self, uid: &str) {
        if let Some((nick, ip)) = self.users.get(uid).map(|u| (u.nick.clone(), u.ip.clone())) {
            self.record_seen(lc(&nick), Seen { nick, ts: now(), what: "quitting".to_string() });
            // Release the user's session slot.
            if let Some(n) = self.sessions.get_mut(&ip) {
                *n -= 1;
                if *n == 0 {
                    self.sessions.remove(&ip);
                }
            }
        }
        self.users.remove(uid);
        self.accounts.remove(uid);
        for c in self.channels.values_mut() {
            c.members.remove(uid);
            c.ops.remove(uid);
            c.voices.remove(uid);
        }
    }

    // Forget a channel outright (the engine calls this once it's confirmed truly
    // empty on the ircd — no members and no resident services bot).
    pub fn remove_channel(&mut self, channel: &str) {
        self.channels.remove(&lc(channel));
    }

    pub fn nick_of(&self, uid: &str) -> Option<&str> {
        self.users.get(uid).map(|u| u.nick.as_str())
    }

    // A user's currently identified account, if any. Kept in step with the
    // accountname metadata the engine emits (login sets it, logout clears it).
    pub fn account_of(&self, uid: &str) -> Option<&str> {
        self.accounts.get(uid).map(String::as_str)
    }

    // Uids of every live session currently identified to `account`.
    pub fn uids_logged_into(&self, account: &str) -> Vec<String> {
        self.accounts
            .iter()
            .filter(|(_, a)| a.eq_ignore_ascii_case(account))
            .map(|(uid, _)| uid.clone())
            .collect()
    }

    pub fn set_account(&mut self, uid: &str, account: &str) {
        self.accounts.insert(uid.to_string(), account.to_string());
    }

    pub fn clear_account(&mut self, uid: &str) {
        self.accounts.remove(uid);
    }

    // A user joined a channel: record membership (and op status) and last-seen.
    pub fn channel_join(&mut self, channel: &str, uid: &str, op: bool) {
        let c = self.channels.entry(lc(channel)).or_default();
        c.members.insert(uid.to_string());
        if op {
            c.ops.insert(uid.to_string());
        }
        if let Some(nick) = self.nick_of(uid).map(str::to_string) {
            self.record_seen(lc(&nick), Seen { nick, ts: now(), what: format!("joining {channel}") });
        }
    }

    // A user left a channel (part/kick): drop membership and record last-seen.
    pub fn channel_part(&mut self, channel: &str, uid: &str) {
        if let Some(c) = self.channels.get_mut(&lc(channel)) {
            c.members.remove(uid);
            c.ops.remove(uid);
            c.voices.remove(uid);
        }
        if let Some(nick) = self.nick_of(uid).map(str::to_string) {
            self.record_seen(lc(&nick), Seen { nick, ts: now(), what: format!("leaving {channel}") });
        }
    }

    // A channel was renamed in place: carry its membership tracking to the new
    // name so status/enforcement keep working under it.
    pub fn channel_rename(&mut self, old: &str, new: &str) {
        let (ko, kn) = (lc(old), lc(new));
        if ko == kn {
            return;
        }
        if let Some(c) = self.channels.remove(&ko) {
            self.channels.insert(kn, c);
        }
    }

    // Set or clear a user's channel-operator status (FMODE +o/-o).
    pub fn set_op(&mut self, channel: &str, uid: &str, op: bool) {
        let c = self.channels.entry(lc(channel)).or_default();
        if op {
            c.ops.insert(uid.to_string());
        } else {
            c.ops.remove(uid);
        }
    }

    // Whether `uid` currently holds operator status in `channel`.
    pub fn is_op(&self, channel: &str, uid: &str) -> bool {
        self.channels.get(&lc(channel)).is_some_and(|c| c.ops.contains(uid))
    }

    // Set or clear a user's voice status (+v).
    pub fn set_voice(&mut self, channel: &str, uid: &str, voice: bool) {
        let c = self.channels.entry(lc(channel)).or_default();
        if voice {
            c.voices.insert(uid.to_string());
        } else {
            c.voices.remove(uid);
        }
    }

    // Whether `uid` currently holds voice in `channel`.
    pub fn is_voiced(&self, channel: &str, uid: &str) -> bool {
        self.channels.get(&lc(channel)).is_some_and(|c| c.voices.contains(uid))
    }

    // Record a line spoken in `channel` by `nick`, for BOTSTATS. The per-nick map
    // is capped so a busy channel can't grow it without bound.
    pub fn record_line(&mut self, channel: &str, nick: &str, msg: &str) {
        const TALKER_CAP: usize = 512;
        let a = self.chan_activity.entry(lc(channel)).or_default();
        a.lines = a.lines.saturating_add(1);
        if a.talkers.len() < TALKER_CAP || a.talkers.contains_key(nick) {
            *a.talkers.entry(nick.to_string()).or_insert(0) += 1;
        }
        // Channel-scoped last message (bounded, truncated) for SEEN.
        let seen = self.chan_seen.entry(lc(channel)).or_default();
        if seen.len() < TALKER_CAP || seen.contains_key(&lc(nick)) {
            seen.insert(lc(nick), ChanSeen { nick: nick.to_string(), ts: now(), msg: msg.chars().take(300).collect() });
        }
    }

    pub fn channel_seen(&self, channel: &str, nick: &str) -> Option<&ChanSeen> {
        self.chan_seen.get(&lc(channel))?.get(&lc(nick))
    }

    // Increment a shared stat counter.
    pub fn bump(&mut self, key: &str) {
        *self.stats.entry(key.to_string()).or_insert(0) += 1;
    }

    // The raw shared counters (sorted). Gauges are merged in by the reader.
    pub fn stat_counters(&self) -> &BTreeMap<String, u64> {
        &self.stats
    }

    // Seed the counters from persisted state at startup, so they survive restarts.
    pub fn seed_stats(&mut self, stats: BTreeMap<String, u64>) {
        self.stats = stats;
    }

    // Restore the recent-incident ring (and its id counter) from a persisted
    // snapshot at startup, so OperServ LOGSEARCH survives a restart.
    pub fn seed_incidents(&mut self, data: (u64, Vec<(String, u64, String)>)) {
        let (seq, incidents) = data;
        self.incident_seq = seq;
        self.incidents = incidents.into_iter().map(|(id, ts, summary)| Incident { id, ts, summary }).collect();
    }

    // Snapshot the live incident ring (id counter, incidents oldest-first) for
    // persistence.
    pub fn incidents_snapshot(&self) -> (u64, Vec<(String, u64, String)>) {
        (self.incident_seq, self.incidents.iter().map(|i| (i.id.clone(), i.ts, i.summary.clone())).collect())
    }

    // BOTSTATS view: (total lines, top talkers by count, descending).
    pub fn channel_activity(&self, channel: &str) -> Option<(u64, Vec<(String, u64)>)> {
        let a = self.chan_activity.get(&lc(channel))?;
        let mut top: Vec<(String, u64)> = a.talkers.iter().map(|(n, v)| (n.clone(), *v)).collect();
        top.sort_by(|x, y| y.1.cmp(&x.1).then_with(|| x.0.cmp(&y.0)));
        top.truncate(10);
        Some((a.lines, top))
    }

    // Seed per-channel activity from persisted state at startup.
    pub fn seed_chan_activity(&mut self, data: crate::engine::db::ChanStats) {
        self.chan_activity = data
            .into_iter()
            .map(|(c, lines, talkers)| (c, ChanActivity { lines, talkers: talkers.into_iter().collect() }))
            .collect();
    }

    // Snapshot per-channel activity for persistence: each active channel's line
    // count and its top talkers (capped, so a busy channel bounds the event).
    pub fn chan_activity_snapshot(&self) -> crate::engine::db::ChanStats {
        self.chan_activity
            .iter()
            .filter(|(_, a)| a.lines > 0)
            .map(|(c, a)| {
                let mut talkers: Vec<(String, u64)> = a.talkers.iter().map(|(n, v)| (n.clone(), *v)).collect();
                talkers.sort_by(|x, y| y.1.cmp(&x.1).then_with(|| x.0.cmp(&y.0)));
                talkers.truncate(50);
                (c.clone(), a.lines, talkers)
            })
            .collect()
    }

    // Uids currently in `channel`.
    pub fn channel_members(&self, channel: &str) -> impl Iterator<Item = &str> {
        self.channels.get(&lc(channel)).into_iter().flat_map(|c| c.members.iter().map(String::as_str))
    }

    // How many uids currently hold op in `channel`.
    pub fn op_count(&self, channel: &str) -> usize {
        self.channels.get(&lc(channel)).map_or(0, |c| c.ops.len())
    }

    // One ChanFix sampling pass: every tracked score decays by 1; every currently-
    // opped user's identity (its account, else its host) gains CHANFIX_BUMP — a net
    // +1 while opped, -1 while idle, so trusted regulars rise and stale ops fade.
    pub fn chanfix_sample(&mut self) {
        for scores in self.chanfix.values_mut() {
            for v in scores.values_mut() {
                *v = v.saturating_sub(1);
            }
        }
        let mut samples: Vec<(String, String)> = Vec::new();
        for (chan, c) in &self.channels {
            for uid in &c.ops {
                if let Some(id) = self.accounts.get(uid).cloned().or_else(|| self.users.get(uid).map(|u| u.host.clone())) {
                    samples.push((chan.clone(), id));
                }
            }
        }
        for (chan, id) in samples {
            let s = self.chanfix.entry(chan).or_default().entry(id).or_insert(0);
            *s = (*s + CHANFIX_BUMP).min(CHANFIX_MAX);
        }
        for scores in self.chanfix.values_mut() {
            scores.retain(|_, v| *v > 0);
        }
        self.chanfix.retain(|_, m| !m.is_empty());
    }

    // A channel's ChanFix scores (identity -> score), highest first.
    pub fn chanfix_scores(&self, channel: &str) -> Vec<(String, u32)> {
        let mut v: Vec<(String, u32)> = self.chanfix.get(&lc(channel)).into_iter().flat_map(|m| m.iter().map(|(k, &s)| (k.clone(), s))).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v
    }

    pub fn set_channel_key(&mut self, channel: &str, key: Option<String>) {
        self.channels.entry(lc(channel)).or_default().key = key;
    }

    pub fn channel_key(&self, channel: &str) -> Option<&str> {
        self.channels.get(&lc(channel)).and_then(|c| c.key.as_deref())
    }

    pub fn last_seen(&self, nick: &str) -> Option<&Seen> {
        self.seen.get(&lc(nick))
    }

    // Record a last-seen entry, bounding the map so distinct-nick churn (a client
    // cycling nicks, a botnet) can't grow it without limit. When it overflows, the
    // stalest quarter is pruned in one pass — amortising the O(n) sort so the common
    // insert stays O(1). SEEN is best-effort, so forgetting the oldest is safe.
    fn record_seen(&mut self, key: String, entry: Seen) {
        self.seen.insert(key, entry);
        if self.seen.len() > SEEN_CAP {
            let mut by_ts: Vec<(String, u64)> = self.seen.iter().map(|(k, s)| (k.clone(), s.ts)).collect();
            by_ts.sort_unstable_by_key(|(_, ts)| *ts);
            for (k, _) in by_ts.into_iter().take(SEEN_CAP / 4) {
                self.seen.remove(&k);
            }
        }
    }
}

// The module-facing network view. Reads forward to Network's own accessors,
// with the seen record projected into a plain view.
impl NetView for Network {
    fn oper_accounts(&self) -> Vec<String> {
        self.config_opers.keys().cloned().collect()
    }
    fn config_oper_privs(&self, account: &str) -> Privs {
        self.config_opers
            .iter()
            .find(|(a, _)| a.eq_ignore_ascii_case(account))
            .map(|(_, p)| *p)
            .unwrap_or_default()
    }
    fn uid_by_nick(&self, nick: &str) -> Option<&str> {
        Network::uid_by_nick(self, nick)
    }
    fn nick_of(&self, uid: &str) -> Option<&str> {
        Network::nick_of(self, uid)
    }
    fn ban_target(&self, uid: &str) -> Option<echo_api::BanTarget<'_>> {
        Network::ban_target(self, uid)
    }
    fn host_of(&self, uid: &str) -> Option<&str> {
        Network::host_of(self, uid)
    }
    fn ident_of(&self, uid: &str) -> Option<&str> {
        Network::ident_of(self, uid)
    }
    fn account_of(&self, uid: &str) -> Option<&str> {
        Network::account_of(self, uid)
    }
    fn uids_logged_into(&self, account: &str) -> Vec<String> {
        Network::uids_logged_into(self, account)
    }
    fn channels_of(&self, uid: &str) -> Vec<String> {
        Network::channels_of(self, uid)
    }
    fn is_op(&self, channel: &str, uid: &str) -> bool {
        Network::is_op(self, channel, uid)
    }
    fn channel_members(&self, channel: &str) -> Vec<String> {
        Network::channel_members(self, channel).map(str::to_string).collect()
    }
    fn channel_key(&self, channel: &str) -> Option<&str> {
        Network::channel_key(self, channel)
    }
    fn last_seen(&self, nick: &str) -> Option<SeenView> {
        Network::last_seen(self, nick).map(|s| SeenView {
            nick: s.nick.clone(),
            ts: s.ts,
            what: s.what.clone(),
        })
    }
    fn channel_seen(&self, channel: &str, nick: &str) -> Option<ChanSeenView> {
        Network::channel_seen(self, channel, nick).map(|s| ChanSeenView {
            nick: s.nick.clone(),
            ts: s.ts,
            msg: s.msg.clone(),
        })
    }
    fn channel_activity(&self, channel: &str) -> Option<(u64, Vec<(String, u64)>)> {
        Network::channel_activity(self, channel)
    }
    fn stat_counters(&self) -> Vec<(String, u64)> {
        Network::stat_counters(self).iter().map(|(k, v)| (k.clone(), *v)).collect()
    }
    fn session_count(&self, ip: &str) -> u32 {
        Network::session_count(self, ip)
    }
    fn sessions_over(&self, min: u32) -> Vec<(String, u32)> {
        Network::sessions_over(self, min)
    }
    fn search_incidents(&self, pattern: &str, limit: usize) -> Vec<IncidentView> {
        Network::search_incidents(self, pattern, limit)
    }
    fn chanfix_scores(&self, channel: &str) -> Vec<(String, u32)> {
        Network::chanfix_scores(self, channel)
    }
    fn op_count(&self, channel: &str) -> usize {
        Network::op_count(self, channel)
    }
    fn help_services(&self) -> Vec<String> {
        self.help_catalog.iter().map(|(n, _, _)| n.clone()).collect()
    }
    fn service_help(&self, service: &str) -> Option<(&'static str, &'static [HelpEntry])> {
        self.help_catalog
            .iter()
            .find(|(n, _, _)| n.eq_ignore_ascii_case(service))
            .map(|(_, b, t)| (*b, *t))
    }
}
