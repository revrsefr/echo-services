// One-off importer: read an Anope `db_json` (anope.json) and write a fresh Echo
// event log with the equivalent accounts, channels, bots and memos. Read-only on
// the source; the daemon replays the produced log on next start. Passwords are
// deliberately NOT migrated — Anope stores one-way hashes (hmac/bcrypt/argon2)
// that can't become SCRAM verifiers, so migrated accounts authenticate by certfp
// or an external authority (or must reset their password).

use crate::engine::db::{Account, Bot, ChanSettings, Db, Event, Vhost};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Default)]
pub struct Summary {
    pub accounts: usize,
    pub grouped_nicks: usize,
    pub certs: usize,
    pub vhosts: usize,
    pub channels: usize,
    pub settings: usize,
    pub access: usize,
    pub mlocked: usize,
    pub bots: usize,
    pub memos: usize,
    pub skipped: Vec<String>,
    // What the produced log actually replays to (round-trip check).
    pub loaded_accounts: usize,
    pub loaded_channels: usize,
    pub loaded_bots: usize,
}

// Nicks fedserv provides itself as service agents — never import them as bots.
const SERVICE_NICKS: &[&str] = &[
    "nickserv", "chanserv", "botserv", "operserv", "hostserv", "memoserv", "helpserv",
    "groupserv", "statserv", "infoserv", "global", "chanfix", "diceserv", "reportserv",
];

// Anope ModeLock name -> InspIRCd mode char, for the param-less locks.
// Param modes (FLOOD/JOINFLOOD) are handled separately by param_mode_char.
fn mode_char(name: &str) -> Option<char> {
    Some(match name {
        "NOEXTERNAL" => 'n',
        "TOPIC" | "TOPICLOCK" => 't',
        "NOCTCP" => 'C',
        "NONOTICE" => 'T',
        "SECRET" => 's',
        "PRIVATE" => 'p',
        "MODERATED" => 'm',
        "INVITEONLY" | "INVITE" => 'i',
        "BLOCKCOLOR" => 'c',
        "REGISTEREDONLY" | "REGONLY" | "REGISTERED" => 'R',
        "SSLONLY" | "SSL" => 'z',
        "PERMANENT" | "PERM" => 'P',
        "NOKICK" => 'Q',
        "STRIPCOLOR" => 'S',
        _ => return None,
    })
}

// Param-carrying mode locks: the ircd mode takes an argument, so the lock keeps
// the stored value and re-asserts `+<char> <value>`.
fn param_mode_char(name: &str) -> Option<char> {
    Some(match name {
        "FLOOD" => 'f',
        "JOINFLOOD" => 'j',
        _ => return None,
    })
}

// A non-empty, non-"None" string field (Anope stores genuine text as strings).
fn field<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str).filter(|s| !s.is_empty() && *s != "None")
}
// An id/textual field normalized to an owned String — Anope stores ids as ints.
fn id_field(v: &Value, k: &str) -> Option<String> {
    match v.get(k) {
        Some(Value::String(s)) if !s.is_empty() && s != "None" => Some(s.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        _ => None,
    }
}
// A number (int JSON, or a numeric string).
fn num(v: &Value, k: &str) -> u64 {
    match v.get(k) {
        Some(Value::Number(n)) => n.as_u64().unwrap_or(0),
        Some(Value::String(s)) => s.parse().unwrap_or(0),
        _ => 0,
    }
}
// A truthy flag (JSON bool, or the strings "True"/"1").
fn flag(v: &Value, k: &str) -> bool {
    match v.get(k) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s == "True" || s == "1",
        _ => false,
    }
}
fn records<'a>(data: &'a Value, kind: &str) -> Vec<&'a Value> {
    match data.get(kind) {
        Some(Value::Array(a)) => a.iter().collect(),
        Some(Value::Object(o)) => o.values().collect(),
        _ => Vec::new(),
    }
}

// Map one Anope access entry to echo's op/voice tiers, whatever provider stored
// it: numeric access/access (by the channel's AUTOOP/AUTOVOICE thresholds), the
// XOP words, or a flags string. None = not representable (sub-voice level or
// unknown format) — the caller reports it rather than dropping it silently.
fn access_role(data: &str, op_at: i64, voice_at: i64) -> Option<&'static str> {
    let d = data.trim();
    if let Ok(level) = d.parse::<i64>() {
        return if level >= op_at { Some("op") } else if level >= voice_at { Some("voice") } else { None };
    }
    match d.to_ascii_uppercase().as_str() {
        // XOP tiers: everything op-or-above collapses to op; VOP is voice.
        "QOP" | "OWNER" | "FOUNDER" | "COFOUNDER" | "SOP" | "AOP" | "HOP" => Some("op"),
        "VOP" => Some("voice"),
        _ => {
            // flags/flags: privilege letters. Owner/protect/op ⇒ op; halfop/voice ⇒ voice.
            let has = |set: &str| d.chars().any(|c| set.contains(c.to_ascii_lowercase()));
            if has("qaof") { Some("op") } else if has("hv") { Some("voice") } else { None }
        }
    }
}

// AUTOOP / AUTOVOICE thresholds from a channel's "levels" string ("... AUTOOP 5 ...").
fn thresholds(levels: &str) -> (i64, i64) {
    let toks: Vec<&str> = levels.split_whitespace().collect();
    let find = |name: &str, dflt: i64| {
        toks.windows(2)
            .find(|w| w[0] == name)
            .and_then(|w| w[1].parse().ok())
            .unwrap_or(dflt)
    };
    (find("AUTOOP", 5), find("AUTOVOICE", 3))
}

pub fn import_anope(anope_path: &str, out_path: &str, node: &str) -> std::io::Result<Summary> {
    let raw = std::fs::read_to_string(anope_path)?;
    let root: Value =
        serde_json::from_str(&raw).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let data = root.get("data").cloned().unwrap_or(Value::Null);

    let _ = std::fs::remove_file(out_path);
    let mut db = Db::open(out_path, node);
    let mut sum = Summary::default();

    // uniqueid -> account display name, to resolve founders/certs/aliases.
    let mut id_to_display: HashMap<String, String> = HashMap::new();
    for nc in records(&data, "NickCore") {
        if let (Some(id), Some(disp)) = (id_field(nc, "uniqueid"), field(nc, "display")) {
            id_to_display.insert(id, disp.to_string());
        }
    }

    // Per-account vhost and last-seen, gathered from the nick aliases.
    let mut vhost_of: HashMap<String, (String, String, u64)> = HashMap::new(); // display -> (host, setter, ts)
    let mut last_seen_of: HashMap<String, u64> = HashMap::new();
    for na in records(&data, "NickAlias") {
        let Some(disp) = id_field(na, "ncid").and_then(|id| id_to_display.get(&id).cloned()) else { continue };
        let seen = num(na, "last_seen");
        let e = last_seen_of.entry(disp.clone()).or_insert(0);
        *e = (*e).max(seen);
        if let Some(host) = field(na, "vhost_host") {
            let full = match field(na, "vhost_ident") {
                Some(ident) => format!("{ident}@{host}"),
                None => host.to_string(),
            };
            vhost_of.insert(disp.clone(), (full, field(na, "vhost_creator").unwrap_or("import").to_string(), num(na, "vhost_time")));
        }
    }

    // Accounts.
    for nc in records(&data, "NickCore") {
        let Some(name) = field(nc, "display") else { continue };
        let ts = num(nc, "registered");
        let vhost = vhost_of.get(name).map(|(host, setter, vts)| {
            sum.vhosts += 1;
            Vhost { host: host.clone(), setter: setter.clone(), ts: *vts, expires: None }
        });
        let account = Account {
            name: name.to_string(),
            email: field(nc, "email").map(str::to_string),
            ts,
            home: node.to_string(),
            scram256: None,
            scram512: None,
            certfps: Vec::new(),
            verified: true,
            ajoin: Vec::new(),
            suspension: None,
            memos: Vec::new(),
            memo_ignore: Vec::new(),
            // Anope applies nickserv `defaults` at registration and serializes the
            // result, so a stored flag IS the account's state and absence means
            // off. Derive every SET flag echo models the same way — never hardcode,
            // or accounts that never toggled the flag get the wrong value.
            memo_notify: flag(nc, "MEMO_SIGNON"),
            memo_limit: match num(nc, "memomax") { 0 => None, n => Some(n as u32) },
            greet: String::new(),
            no_autoop: !flag(nc, "AUTOOP"),
            no_protect: !flag(nc, "PROTECT"),
            hide_status: flag(nc, "HIDE_MASK"),
            vhost,
            vhost_request: None,
            last_seen: last_seen_of.get(name).copied().unwrap_or(ts),
            noexpire: false,
            expiry_warned: false,
            oper_note: None,
        };
        db.migrate_append(Event::AccountRegistered(Box::new(account)))?;
        sum.accounts += 1;
    }

    // Grouped nicks (aliases whose nick isn't the account's display name).
    for na in records(&data, "NickAlias") {
        let (Some(nick), Some(disp)) = (field(na, "nick"), id_field(na, "ncid").and_then(|id| id_to_display.get(&id).cloned())) else { continue };
        if !nick.eq_ignore_ascii_case(&disp) {
            db.migrate_append(Event::NickGrouped { nick: nick.to_string(), account: disp })?;
            sum.grouped_nicks += 1;
        }
    }

    // Certificate fingerprints.
    for cert in records(&data, "NSCert") {
        let (Some(fp), Some(disp)) = (field(cert, "fingerprint"), id_field(cert, "account").and_then(|id| id_to_display.get(&id).cloned())) else { continue };
        db.migrate_append(Event::CertAdded { account: disp, fp: fp.to_ascii_lowercase() })?;
        sum.certs += 1;
    }

    // Channels (+ description, topic, assigned bot); remember access thresholds.
    let mut chan_levels: HashMap<String, (i64, i64)> = HashMap::new();
    for ci in records(&data, "ChannelInfo") {
        let Some(name) = field(ci, "name") else { continue };
        let Some(founder) = id_field(ci, "founderid").and_then(|id| id_to_display.get(&id).cloned()) else {
            sum.skipped.push(format!("channel {name}: founder id unresolved"));
            continue;
        };
        chan_levels.insert(name.to_string(), thresholds(field(ci, "levels").unwrap_or("")));
        db.migrate_append(Event::ChannelRegistered { name: name.to_string(), founder, ts: num(ci, "registered") })?;
        if let Some(desc) = field(ci, "description") {
            db.migrate_append(Event::ChannelDescSet { channel: name.to_string(), desc: desc.to_string() })?;
        }
        if let Some(topic) = field(ci, "last_topic") {
            db.migrate_append(Event::ChannelTopicSet { channel: name.to_string(), topic: topic.to_string() })?;
        }
        if let Some(bot) = field(ci, "bi") {
            if !SERVICE_NICKS.contains(&bot.to_ascii_lowercase().as_str()) {
                db.migrate_append(Event::ChannelBotAssigned { channel: name.to_string(), bot: bot.to_string() })?;
            }
        }
        // SET flags (Anope stores each as a present-and-true bool). A few have no
        // echo equivalent (echo has no persist concept, no secure-founder toggle,
        // no keep-modes, and fantasy is always on) — report each so nothing is
        // dropped silently.
        for (anope, note) in [
            ("PERSIST", "PERSIST (+P) — echo channels persist as records; re-add a +P mlock if the channel must stay physically open"),
            ("SECUREFOUNDER", "SECUREFOUNDER — echo has no secure-founder toggle"),
            ("CS_KEEP_MODES", "KEEP_MODES — echo has no keep-modes toggle"),
            ("BS_FANTASY", "FANTASY off — echo fantasy (!cmds) is always enabled"),
        ] {
            if flag(ci, anope) {
                sum.skipped.push(format!("channel {name}: {note}"));
            }
        }
        let any = |names: &[&str]| names.iter().any(|n| flag(ci, n));
        let settings = ChanSettings {
            signkick: any(&["SIGNKICK"]),
            private: any(&["PRIVATE", "CS_PRIVATE"]),
            peace: any(&["PEACE"]),
            secureops: any(&["SECUREOPS", "CS_SECUREOPS"]),
            restricted: any(&["RESTRICTED", "CS_RESTRICTED"]),
            noautoop: any(&["NOAUTOOP", "CS_NOAUTOOP"]),
            keeptopic: any(&["KEEPTOPIC"]),
            topiclock: any(&["TOPICLOCK", "CS_TOPICLOCK"]),
            bot_greet: any(&["BS_GREET"]),
            nobot: any(&["BS_NOBOT", "NOBOT"]),
        };
        if settings != ChanSettings::default() {
            db.migrate_append(Event::ChannelSettingsSet { channel: name.to_string(), settings })?;
            sum.settings += 1;
        }
        if flag(ci, "CS_NO_EXPIRE") {
            db.migrate_append(Event::ChannelNoExpire { channel: name.to_string(), on: true })?;
        }
        sum.channels += 1;
    }

    // Channel access -> op/voice by the channel's own AUTOOP/AUTOVOICE thresholds.
    for ca in records(&data, "ChanAccess") {
        let (Some(chan), Some(mask)) = (field(ca, "ci"), field(ca, "mask")) else { continue };
        let data = field(ca, "data").unwrap_or("");
        let (op_at, voice_at) = chan_levels.get(chan).copied().unwrap_or((5, 3));
        let Some(role) = access_role(data, op_at, voice_at) else {
            // echo access is op/voice only; a lower tier (or an unknown format)
            // can't be represented — report it instead of dropping it silently.
            sum.skipped.push(format!("access {chan} {mask} ({data:?}): below voice tier / unmapped — echo access is op/voice only"));
            continue;
        };
        db.migrate_append(Event::ChannelAccessAdd { channel: chan.to_string(), account: mask.to_string(), level: role.to_string() })?;
        sum.access += 1;
    }

    // Mode locks: aggregate the +modes per channel. Param modes (+f flood,
    // +j joinflood) carry their stored value so the lock re-enforces verbatim.
    let mut locks: HashMap<String, (String, Vec<(char, String)>)> = HashMap::new();
    for ml in records(&data, "ModeLock") {
        let (Some(chan), Some(name)) = (field(ml, "ci"), field(ml, "name")) else { continue };
        if !flag(ml, "set") {
            continue;
        }
        if let Some(ch) = mode_char(name) {
            locks.entry(chan.to_string()).or_default().0.push(ch);
        } else if let Some(ch) = param_mode_char(name) {
            let Some(param) = field(ml, "param") else {
                sum.skipped.push(format!("modelock {chan} {name}: param mode with no value"));
                continue;
            };
            let entry = locks.entry(chan.to_string()).or_default();
            entry.0.push(ch);
            entry.1.push((ch, param.to_string()));
        } else {
            sum.skipped.push(format!("modelock {chan} {name}: unmapped mode"));
        }
    }
    for (chan, (on, params)) in &locks {
        db.migrate_append(Event::ChannelMlock {
            name: chan.clone(),
            on: on.clone(),
            off: String::new(),
            params: params.clone(),
        })?;
        sum.mlocked += 1;
    }

    // BotServ bots (skipping the service pseudo-clients fedserv provides itself).
    for bi in records(&data, "BotInfo") {
        let Some(nick) = field(bi, "nick") else { continue };
        if SERVICE_NICKS.contains(&nick.to_ascii_lowercase().as_str()) {
            continue;
        }
        db.migrate_append(Event::BotAdded(Bot {
            nick: nick.to_string(),
            user: field(bi, "user").unwrap_or("bot").to_string(),
            host: field(bi, "host").unwrap_or("services.").to_string(),
            gecos: field(bi, "realname").unwrap_or("Bot").to_string(),
            private: flag(bi, "oper_only"),
        }))?;
        sum.bots += 1;
    }

    // Memos.
    let mut memo_index: HashMap<String, usize> = HashMap::new();
    for m in records(&data, "Memo") {
        let (Some(owner), Some(text)) = (field(m, "owner"), field(m, "text")) else { continue };
        let idx = memo_index.entry(owner.to_string()).or_insert(0);
        db.migrate_append(Event::MemoSent {
            account: owner.to_string(),
            from: field(m, "sender").unwrap_or("unknown").to_string(),
            text: text.to_string(),
            ts: num(m, "time"),
            receipt: flag(m, "receipt"),
        })?;
        if !flag(m, "unread") {
            db.migrate_append(Event::MemoRead { account: owner.to_string(), index: *idx })?;
        }
        *idx += 1;
        sum.memos += 1;
    }

    // Transparency: name every Anope record type that echo has no concept of, so
    // the operator sees exactly what will not carry over rather than finding out
    // later. These are either ephemeral (activity, network counters, third-party
    // caches) or a field echo doesn't model — nothing silently vanishes.
    for m in records(&data, "NSMiscData") {
        let who = field(m, "nc").unwrap_or("?");
        let what = field(m, "name").unwrap_or("misc field");
        sum.skipped.push(format!("account {who}: {what} — echo has no per-account misc field"));
    }
    let unmodelled = [
        ("SeenInfo", "last-seen/activity history (re-accrues live)"),
        ("Stats", "network max-user counters (ephemeral)"),
        ("YouTubeCache", "third-party YouTube module cache"),
        ("YouTubeChanStats", "third-party YouTube module stats"),
        ("YouTubeUserStats", "third-party YouTube module stats"),
    ];
    for (kind, note) in unmodelled {
        let n = records(&data, kind).len();
        if n > 0 {
            sum.skipped.push(format!("{n} {kind} record(s) not migrated: {note}"));
        }
    }

    // Round-trip check: reopen the produced log and confirm it replays to state
    // (this is exactly what the daemon does on start).
    drop(db);
    let check = Db::open(out_path, node);
    sum.loaded_accounts = check.accounts().count();
    sum.loaded_channels = check.channels().count();
    sum.loaded_bots = check.bots().count();
    Ok(sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal Anope db_json (matching real types: int ids, bool flags) migrates
    // to a log that replays to the expected accounts/channels/bots.
    #[test]
    fn imports_a_minimal_anope_db() {
        let anope = r##"{"data":{
            "NickCore":[{"uniqueid":100,"display":"alice","email":"a@x.io","registered":1000,"AUTOOP":true,"memomax":20,"HIDE_MASK":true}],
            "NickAlias":[{"nick":"alice","ncid":100,"last_seen":2000,"vhost_host":"cool.host","vhost_ident":"al","vhost_creator":"alice","vhost_time":1500}],
            "NSCert":[{"fingerprint":"AABBCC","account":100}],
            "ChannelInfo":[{"name":"#chan","founderid":100,"registered":1100,"description":"a place","levels":"AUTOOP 5 AUTOVOICE 3","bi":"Botty","KEEPTOPIC":true,"PEACE":true,"CS_NO_EXPIRE":true,"PERSIST":true}],
            "ChanAccess":[{"ci":"#chan","mask":"bob","data":"5"},{"ci":"#chan","mask":"carol","data":"3"}],
            "ModeLock":[{"ci":"#chan","name":"NOEXTERNAL","set":true},{"ci":"#chan","name":"TOPIC","set":true},{"ci":"#chan","name":"FLOOD","set":true,"param":"5:10"}],
            "BotInfo":[{"nick":"Botty","user":"b","host":"h","realname":"Bot"},{"nick":"NickServ","user":"n","host":"h","realname":"svc"}],
            "Memo":[{"owner":"alice","sender":"bob","text":"hi","time":3000,"receipt":false,"unread":false}]
        }}"##;
        let dir = std::env::temp_dir();
        let src = dir.join("echo-anope-fixture.json");
        let out = dir.join("echo-migrated-fixture.jsonl");
        std::fs::write(&src, anope).unwrap();

        let s = import_anope(src.to_str().unwrap(), out.to_str().unwrap(), "n1").unwrap();
        assert_eq!((s.accounts, s.certs, s.vhosts, s.channels, s.settings, s.access, s.mlocked, s.bots, s.memos), (1, 1, 1, 1, 1, 2, 1, 1, 1));
        assert_eq!((s.loaded_accounts, s.loaded_channels, s.loaded_bots), (1, 1, 1), "produced log replays cleanly");

        let db = Db::open(out.to_str().unwrap().to_string(), "n1");
        let acct = db.account("alice").expect("alice migrated");
        assert_eq!(acct.email.as_deref(), Some("a@x.io"));
        assert!(acct.scram256.is_none(), "no password migrated (one-way hash)");
        assert!(!acct.no_autoop, "AUTOOP=true keeps auto-op on");
        assert!(acct.hide_status, "HIDE_MASK -> hide status");
        // No PROTECT / MEMO_SIGNON flag on alice: Anope absence = off, so these
        // must migrate off — not echo's register defaults (protect on, notify on).
        assert!(acct.no_protect, "no PROTECT flag -> nick protection off");
        assert!(!acct.memo_notify, "no MEMO_SIGNON flag -> memo notify off");
        assert_eq!(acct.certfps, vec!["aabbcc".to_string()]);
        assert!(acct.vhost.is_some(), "vhost carried from the nick alias");
        let chan = db.channel("#chan").expect("channel migrated");
        assert_eq!(chan.founder, "alice");
        assert_eq!(chan.desc, "a place");
        assert_eq!(chan.lock_on, "ntf", "param-less and param mlocks both kept");
        assert_eq!(chan.lock_params, vec![('f', "5:10".to_string())], "FLOOD param carried");
        assert_eq!(chan.assigned_bot.as_deref(), Some("Botty"));
        assert!(chan.settings.keeptopic && chan.settings.peace, "channel SET flags migrated");
        assert!(!chan.settings.signkick, "unset flags stay default");
        assert!(chan.noexpire, "CS_NO_EXPIRE -> channel noexpire");
        assert!(s.skipped.iter().any(|n| n.contains("PERSIST")), "PERSIST reported as skipped, not silently dropped");
        let mut roles: Vec<_> = chan.access.iter().map(|a| (a.account.as_str(), a.level.as_str())).collect();
        roles.sort();
        assert_eq!(roles, vec![("bob", "op"), ("carol", "voice")], "levels mapped by threshold");
    }

    // Access maps from every Anope provider format, not just numeric access/access.
    #[test]
    fn access_role_covers_numeric_xop_and_flags() {
        // numeric access/access against thresholds (op>=5, voice>=3)
        assert_eq!(access_role("5", 5, 3), Some("op"));
        assert_eq!(access_role("3", 5, 3), Some("voice"));
        assert_eq!(access_role("2", 5, 3), None, "sub-voice level isn't representable");
        // XOP words
        assert_eq!(access_role("AOP", 5, 3), Some("op"));
        assert_eq!(access_role("sop", 5, 3), Some("op"));
        assert_eq!(access_role("VOP", 5, 3), Some("voice"));
        // flags/flags letters
        assert_eq!(access_role("+o", 5, 3), Some("op"));
        assert_eq!(access_role("+v", 5, 3), Some("voice"));
        assert_eq!(access_role("+qao", 5, 3), Some("op"));
        // unknown format is unmapped (reported, not silently dropped)
        assert_eq!(access_role("weird", 5, 3), None);
    }
}
