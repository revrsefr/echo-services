use echo_api::{Sender, ServiceCtx, Store};

// A friendly one-liner (with an example) for each extban, keyed by its ircd name.
// The letter and whether it's offered come live from the ircd's CAPAB set, so this
// only supplies the human description; names the ircd offers but we have no blurb
// for are still listed, just without the sentence.
const DESC: &[(&str, &str)] = &[
    // Matching extbans — they match *who* a user is.
    ("account", "a logged-in account. e.g. +b account:baddie"),
    ("unauthed", "users NOT logged in whose mask matches. e.g. +b unauthed:*!*@*.example"),
    ("realname", "the real name (gecos). e.g. +b realname:*viagra*"),
    ("realmask", "host and real name together, joined by +. e.g. +b realmask:*!*@*.tor+*bot*"),
    ("server", "everyone on a server. e.g. +b server:leaf2.example.net"),
    ("fingerprint", "a TLS client-certificate fingerprint. e.g. +b fingerprint:<hash>"),
    ("channel", "users also in another channel. e.g. +b channel:#trolls"),
    ("banlist", "users banned in another channel. e.g. +b banlist:#other"),
    ("country", "users connecting from a country (GeoIP). e.g. +b country:RU"),
    ("asn", "users on a network operator, by AS number. e.g. +b asn:12345"),
    ("class", "users in a connect class. e.g. +b class:webchat"),
    ("gateway", "users behind a web gateway. e.g. +b gateway:kiwiirc"),
    ("bot", "users flagged as bots (+B). e.g. +b bot:*!*@*"),
    ("oper", "IRC operators. e.g. +b oper:*"),
    ("opertype", "a specific oper type. e.g. +b opertype:NetAdmin"),
    ("securitygroup", "members of a security group. e.g. +b securitygroup:trusted"),
    ("score", "users over a connection-score threshold. e.g. +b score:10"),
    ("team", "members of an account team. e.g. +b team:staff"),
    ("redirect", "ban and send them to another channel. e.g. +b redirect:#overflow:*!*@lots"),
    // Acting extbans — they restrict *what* a user can do.
    ("mute", "can stay and read but not speak. e.g. +b mute:*!*@spam.host"),
    ("nonick", "cannot change nick in the channel. e.g. +b nonick:*!*@*"),
    ("noctcp", "cannot send CTCPs. e.g. +b noctcp:*!*@*"),
    ("nonotice", "cannot send channel notices. e.g. +b nonotice:*!*@*"),
    ("nokick", "cannot use KICK. e.g. +b nokick:*!*@*"),
    ("blockcolor", "colour/formatting in their messages is blocked. e.g. +b blockcolor:*!*@*"),
    ("stripcolor", "colour is stripped from their messages. e.g. +b stripcolor:*!*@*"),
    ("blockinvite", "cannot invite others. e.g. +b blockinvite:*!*@*"),
    ("opmoderated", "their messages reach only ops. e.g. +b opmoderated:*!*@*"),
];

// HELP EXTBANS: explain extended bans and list the ones this network actually
// offers, each with an example, split into matching (who) and acting (what).
pub fn handle(me: &str, from: &Sender, ctx: &mut ServiceCtx, db: &dyn Store) {
    let say = |ctx: &mut ServiceCtx, s: String| ctx.notice(me, from.uid, s);

    say(ctx, "Extended bans (\x02extbans\x02) match users by more than nick!user@host.".to_string());
    say(ctx, "Use one where a ban mask goes: \x02/mode #chan +b <extban>\x02 (also +e/+I), or in \x02ChanServ AKICK\x02 (matching types only).".to_string());
    say(ctx, "Write them by name or letter — \x02account:bad\x02 is the same as \x02R:bad\x02 — and prefix \x02!\x02 to invert (match everyone except).".to_string());

    let mut offered = db.extbans();
    offered.sort_by(|a, b| a.name.cmp(&b.name));
    let (acting, matching): (Vec<_>, Vec<_>) = offered.into_iter().partition(|e| e.acting);

    let line = |ctx: &mut ServiceCtx, e: &echo_api::ExtbanCap| {
        let letter = e.letter.map_or_else(|| "-".to_string(), |c| c.to_string());
        match DESC.iter().find(|(n, _)| n.eq_ignore_ascii_case(&e.name)) {
            Some((_, desc)) => say(ctx, format!("  \x02{}\x02 (\x02{}\x02) — {}", e.name, letter, desc)),
            None => say(ctx, format!("  \x02{}\x02 (\x02{}\x02)", e.name, letter)),
        }
    };

    if matching.is_empty() && acting.is_empty() {
        // We haven't learned the ircd's set yet — show the reference from DESC.
        say(ctx, "\x02Extban types\x02 (your network's exact set is confirmed on link):".to_string());
        for (name, desc) in DESC {
            say(ctx, format!("  \x02{name}\x02 — {desc}"));
        }
        return;
    }
    if !matching.is_empty() {
        say(ctx, "\x02Matching\x02 — match who a user is (work in AKICK and bans):".to_string());
        for e in &matching {
            line(ctx, e);
        }
    }
    if !acting.is_empty() {
        say(ctx, "\x02Acting\x02 — restrict what a user can do (bans only):".to_string());
        for e in &acting {
            line(ctx, e);
        }
    }
    say(ctx, "ChanServ accepts only the extbans this network offers and hasn't disabled.".to_string());
}
