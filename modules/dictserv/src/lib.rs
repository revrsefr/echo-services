//! DictServ answers dictionary, thesaurus and reference lookups by querying a
//! DICT server (RFC 2229) — dict.org by default. Every lookup command maps to one
//! DICT database; the actual network request runs off the reactor (the link layer
//! handles `NetAction::DictLookup`), so a slow server never stalls the engine.
//!
//! Works two ways: `/msg DictServ dict cat` (DictServ replies), or the fantasy
//! `!dict cat` in a channel with an assigned bot (the bot speaks the answer).

use echo_api::{t, HelpEntry, NetView, Sender, Service, ServiceCtx, Store};

// One lookup command: the fantasy/word, the DICT database it queries, and a human
// label shown in the reply. Shared by DictServ and the engine's fantasy router so
// the two never drift.
pub struct Lookup {
    pub cmd: &'static str,
    pub database: &'static str,
    pub label: &'static str,
}

pub const LOOKUPS: &[Lookup] = &[
    Lookup { cmd: "dict", database: "wn", label: "WordNet" },
    Lookup { cmd: "define", database: "gcide", label: "GCIDE" },
    Lookup { cmd: "definitions", database: "*", label: "all dictionaries" },
    Lookup { cmd: "thes", database: "moby-thesaurus", label: "Thesaurus" },
    Lookup { cmd: "element", database: "elements", label: "Elements" },
    Lookup { cmd: "acronym", database: "vera", label: "Acronyms" },
    Lookup { cmd: "jargon", database: "jargon", label: "Jargon File" },
    Lookup { cmd: "term", database: "foldoc", label: "Computing" },
    Lookup { cmd: "bible", database: "easton", label: "Easton's Bible" },
    Lookup { cmd: "biblename", database: "hitchcock", label: "Bible Names" },
    Lookup { cmd: "law", database: "bouvier", label: "Bouvier's Law" },
    Lookup { cmd: "ciainfo", database: "world02", label: "CIA Factbook" },
    Lookup { cmd: "counties", database: "gaz2k-counties", label: "US Counties" },
    Lookup { cmd: "places", database: "gaz2k-places", label: "US Places" },
    Lookup { cmd: "zipcodes", database: "gaz2k-zips", label: "US ZIP codes" },
];

// The lookup a command word maps to, if any. Case-insensitive.
pub fn lookup_for(cmd: &str) -> Option<&'static Lookup> {
    LOOKUPS.iter().find(|l| l.cmd.eq_ignore_ascii_case(cmd))
}

const BLURB: &str = "DictServ looks words up in the dict.org dictionaries. Try \x02dict\x02 <word> (WordNet), \x02define\x02 (GCIDE), \x02thes\x02 (thesaurus), \x02acronym\x02, \x02element\x02, \x02law\x02, \x02bible\x02, and more — \x02LOOKUP\x02 lists them all.";

const TOPICS: &[HelpEntry] = &[
    HelpEntry { cmd: "DICT", summary: "define a word (WordNet)", detail: "Syntax: \x02DICT <word>\x02\nLooks a word up in WordNet. In a channel with a bot, use \x02!dict <word>\x02." },
    HelpEntry { cmd: "DEFINE", summary: "define a word (GCIDE)", detail: "Syntax: \x02DEFINE <word>\x02\nLooks a word up in the GNU Collaborative International Dictionary of English." },
    HelpEntry { cmd: "THES", summary: "thesaurus lookup", detail: "Syntax: \x02THES <word>\x02\nMoby Thesaurus synonyms for a word." },
    HelpEntry { cmd: "LOOKUP", summary: "list every lookup command", detail: "Syntax: \x02LOOKUP\x02\nLists all dictionary, reference and thesaurus lookups DictServ knows." },
];

pub struct DictServ {
    pub uid: String,
}

impl Service for DictServ {
    fn nick(&self) -> &str {
        "DictServ"
    }
    fn uid(&self) -> &str {
        &self.uid
    }
    fn gecos(&self) -> &str {
        "Dictionary Lookups"
    }
    fn help_topics(&self) -> (&'static str, &'static [HelpEntry]) {
        (BLURB, TOPICS)
    }

    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, _net: &dyn NetView, _db: &mut dyn Store) {
        let me = self.uid.as_str();
        let cmd = args.first().copied().unwrap_or("");
        // A lookup command: hand the query to the deferred DICT client, which will
        // reply to the user directly. Arguments (the term) are sent as one string.
        if let Some(l) = lookup_for(cmd) {
            let query = args[1..].join(" ");
            if query.trim().is_empty() {
                ctx.notice(me, from.uid, t!(ctx, "Give a term to look up, e.g. \x02{cmd} cat\x02.", cmd = l.cmd));
                return;
            }
            ctx.dict_lookup(me, from.uid, l.database, l.label, query);
            return;
        }
        match cmd.to_ascii_uppercase().as_str() {
            "LOOKUP" | "LIST" => {
                ctx.notice(me, from.uid, "Lookup commands (use in a channel as \x02!cmd <term>\x02, or here as \x02/msg DictServ cmd <term>\x02):");
                for l in LOOKUPS {
                    ctx.notice(me, from.uid, t!(ctx, "  \x02{cmd}\x02 — {label}", cmd = l.cmd, label = l.label));
                }
            }
            "HELP" | "" => echo_api::help(me, from, ctx, BLURB, TOPICS, args.get(1).copied()),
            other => ctx.notice(me, from.uid, t!(ctx, "I don't know \x02{other}\x02. Try \x02LOOKUP\x02 for the list, or \x02HELP\x02.", other = other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_commands_to_databases_case_insensitively() {
        assert_eq!(lookup_for("dict").unwrap().database, "wn");
        assert_eq!(lookup_for("DEFINE").unwrap().database, "gcide");
        assert_eq!(lookup_for("Thes").unwrap().database, "moby-thesaurus");
        assert_eq!(lookup_for("zipcodes").unwrap().database, "gaz2k-zips");
        assert!(lookup_for("nonsense").is_none());
        assert!(lookup_for("roll").is_none()); // not ours — DiceServ owns that
    }
}
