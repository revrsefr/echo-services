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

// Anope ModeLock name -> InspIRCd mode char, for the param-less locks we can carry.
// Param modes (FLOOD/JOINFLOOD) are skipped: Echo's mlock is char-only.
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
            memo_notify: true,
            memo_limit: match num(nc, "memomax") { 0 => None, n => Some(n as u32) },
            greet: String::new(),
            no_autoop: !flag(nc, "AUTOOP"),
            no_protect: false,
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
        // SET flags (Anope stores each as a present-and-true bool). PERSIST,
        // SECUREFOUNDER, KEEP_MODES and FANTASY have no Echo equivalent — skipped.
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
        let level: i64 = field(ca, "data").and_then(|s| s.parse().ok()).unwrap_or(0);
        let (op_at, voice_at) = chan_levels.get(chan).copied().unwrap_or((5, 3));
        let role = if level >= op_at { "op" } else if level >= voice_at { "voice" } else { continue };
        db.migrate_append(Event::ChannelAccessAdd { channel: chan.to_string(), account: mask.to_string(), level: role.to_string() })?;
        sum.access += 1;
    }

    // Mode locks: aggregate the param-less +modes per channel.
    let mut locks: HashMap<String, String> = HashMap::new();
    for ml in records(&data, "ModeLock") {
        let (Some(chan), Some(name)) = (field(ml, "ci"), field(ml, "name")) else { continue };
        if !flag(ml, "set") {
            continue;
        }
        match mode_char(name) {
            Some(ch) => locks.entry(chan.to_string()).or_default().push(ch),
            None => sum.skipped.push(format!("modelock {chan} {name}: unmapped/param mode")),
        }
    }
    for (chan, on) in &locks {
        db.migrate_append(Event::ChannelMlock { name: chan.clone(), on: on.clone(), off: String::new() })?;
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
        assert_eq!(acct.certfps, vec!["aabbcc".to_string()]);
        assert!(acct.vhost.is_some(), "vhost carried from the nick alias");
        let chan = db.channel("#chan").expect("channel migrated");
        assert_eq!(chan.founder, "alice");
        assert_eq!(chan.desc, "a place");
        assert_eq!(chan.lock_on, "nt", "param-less mlocks kept, FLOOD skipped");
        assert_eq!(chan.assigned_bot.as_deref(), Some("Botty"));
        assert!(chan.settings.keeptopic && chan.settings.peace, "channel SET flags migrated");
        assert!(!chan.settings.signkick, "unset flags stay default (PERSIST has no equivalent, ignored)");
        assert!(chan.noexpire, "CS_NO_EXPIRE -> channel noexpire");
        let mut roles: Vec<_> = chan.access.iter().map(|a| (a.account.as_str(), a.level.as_str())).collect();
        roles.sort();
        assert_eq!(roles, vec![("bob", "op"), ("carol", "voice")], "levels mapped by threshold");
    }
}
