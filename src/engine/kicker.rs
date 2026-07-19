use super::*;

impl Engine {
    // A BotServ kicker verdict for a channel line: if the channel has an active
    // kicker the message trips (and the sender isn't an exempt operator), the
    // assigned bot kicks them — and, once they've been kicked `ttb` times, bans
    // them first. `&mut self` because FLOOD/REPEAT and times-to-ban keep per-user
    // counters. Hot path: one HashMap lookup for a channel with no kickers, and
    // no heap allocation for a returning speaker.
    pub(crate) fn kicker_check(&mut self, from: &str, channel: &str, text: &str) -> Vec<NetAction> {
        // `c` borrows self.db; the other fields (network, chatter, badword_cache)
        // are disjoint, so they can be touched while it is alive — but we stop
        // using `c` before mutating chatter, by copying its config into locals.
        let Some(c) = self.db.channel(channel) else { return Vec::new() };
        let k = &c.kickers;
        if !k.any() {
            return Vec::new();
        }
        if k.dontkickops && self.network.is_op(channel, from) {
            return Vec::new();
        }
        if k.dontkickvoices && self.network.is_voiced(channel, from) {
            return Vec::new();
        }
        let Some(bot) = c.assigned_bot.as_deref() else { return Vec::new() };
        let Some(botuid) = self.network.uid_by_nick(bot).map(str::to_string) else { return Vec::new() };

        // Stateless kickers first (cheapest, and they don't touch counters), then
        // badwords against the channel's compiled regex set (rebuilt only when the
        // list's revision changes).
        let mut reason: Option<&'static str> = k.violation(text);
        if reason.is_none() && k.badwords && !c.badwords.is_empty() {
            let (rev, ts) = (c.badwords_rev, c.ts);
            let key = channel.to_ascii_lowercase();
            if self.badword_cache.get(&key).map(|cb| (cb.rev, cb.ts)) != Some((rev, ts)) {
                let set = db::build_badword_set(&c.badwords);
                self.badword_cache.insert(key.clone(), CachedBadwords { rev, ts, set });
            }
            if self.badword_cache.get(&key).unwrap().set.is_match(text) {
                reason = Some("Watch your language!");
            }
        }
        // Copy the rest of the config out so `c`'s borrow ends before we mutate
        // the counter map below.
        let (flood_lines, flood_secs) = k.flood_thresholds();
        let (flood, repeat, repeat_times) = (k.flood, k.repeat, k.repeat_threshold());
        let (ttb, ban_expire, warn) = (k.ttb, k.ban_expire, k.warn);

        // FLOOD/REPEAT (only if nothing has tripped yet), updating counters.
        if reason.is_none() && (flood || repeat) {
            let now = self.now_secs();
            let state = self.chatter_entry(channel, from);
            if flood {
                if now.saturating_sub(state.flood_start) > flood_secs as u64 {
                    state.flood_start = now;
                    state.flood_lines = 0;
                }
                state.flood_lines = state.flood_lines.saturating_add(1);
                if state.flood_lines >= flood_lines {
                    reason = Some("Stop flooding!");
                }
            }
            if reason.is_none() && repeat {
                let h = ci_hash(text);
                if h == state.last_hash {
                    state.repeats = state.repeats.saturating_add(1);
                } else {
                    state.repeats = 0;
                    state.last_hash = h;
                }
                if state.repeats >= repeat_times {
                    reason = Some("Stop repeating yourself!");
                }
            }
        }

        let Some(reason) = reason else { return Vec::new() };

        // WARN: the first offence gets a private warning from the bot instead of a
        // kick; the next one is kicked for real.
        if warn {
            let already = {
                let state = self.chatter_entry(channel, from);
                let w = state.warned;
                state.warned = true;
                w
            };
            if !already {
                self.bump("botserv.warn");
                return vec![NetAction::Notice { from: botuid, to: from.to_string(), text: format!("Please mind the channel rules — {reason} Next time you'll be kicked.") }];
            }
        }

        // Times-to-ban: after `ttb` kicks the bot bans (an ideal host mask) before
        // kicking, and schedules the unban if BANEXPIRE is set.
        let mut out = Vec::new();
        if ttb > 0 {
            let kicks = {
                let state = self.chatter_entry(channel, from);
                state.kicks = state.kicks.saturating_add(1);
                state.kicks
            };
            if kicks >= ttb {
                self.chatter_entry(channel, from).kicks = 0;
                if let Some(host) = self.network.host_of(from).map(str::to_string) {
                    let mask = format!("*!*@{host}");
                    out.push(NetAction::ChannelMode { from: botuid.clone(), channel: channel.to_string(), modes: format!("+b {mask}") });
                    self.bump("botserv.ban");
                    if ban_expire > 0 {
                        let at = self.now_secs() + ban_expire as u64;
                        self.pending_unbans.push(PendingUnban { at, from: botuid.clone(), channel: channel.to_string(), mask });
                    }
                }
            }
        }
        out.push(NetAction::Kick { from: botuid, channel: channel.to_string(), uid: from.to_string(), reason: reason.to_string() });
        self.bump("botserv.kick");
        out
    }

    // An auto-response for a channel line: if it matches a TRIGGER pattern, the
    // assigned bot says the trigger's response (with $nick substituted). Only the
    // first matching trigger fires. Cache rebuilt only when the list changes.
    pub(crate) fn trigger_response(&mut self, from: &str, channel: &str, text: &str) -> Option<NetAction> {
        let c = self.db.channel(channel)?;
        if c.triggers.is_empty() {
            return None;
        }
        let bot = c.assigned_bot.as_deref()?;
        let botuid = self.network.uid_by_nick(bot)?.to_string();
        let (rev, ts) = (c.triggers_rev, c.ts);
        let key = channel.to_ascii_lowercase();
        if self.trigger_cache.get(&key).map(|ct| (ct.rev, ct.ts)) != Some((rev, ts)) {
            let entries = c
                .triggers
                .iter()
                .filter_map(|t| {
                    regex::RegexBuilder::new(&t.pattern)
                        .case_insensitive(true)
                        .size_limit(db::BADWORD_SIZE_LIMIT)
                        .build()
                        .ok()
                        .map(|re| TriggerRt { re, response: t.response.clone(), cooldown: t.cooldown, last_fired: 0 })
                })
                .collect();
            self.trigger_cache.insert(key.clone(), CachedTriggers { rev, ts, entries });
        }
        let now = self.now_secs();
        let nick = self.network.nick_of(from).unwrap_or(from).to_string();

        // First matching trigger wins; $1..$9 fill from capture groups, $nick from
        // the speaker. A trigger still cooling down suppresses the response.
        let cached = self.trigger_cache.get_mut(&key).unwrap();
        let mut response = None;
        for e in cached.entries.iter_mut() {
            if let Some(caps) = e.re.captures(text) {
                if now.saturating_sub(e.last_fired) < e.cooldown as u64 {
                    return None;
                }
                e.last_fired = now;
                let mut resp = e.response.clone();
                // High group numbers first, so `$1` doesn't rewrite the prefix of `$10`.
                for i in (1..caps.len()).rev() {
                    resp = resp.replace(&format!("${i}"), caps.get(i).map_or("", |m| m.as_str()));
                }
                response = Some(resp.replace("$nick", &nick));
                break;
            }
        }
        let response = response?;
        self.bump("botserv.trigger");
        Some(NetAction::Privmsg { from: botuid, to: channel.to_string(), text: response })
    }

    // Get (or lazily create) a speaker's counters in a channel. get_mut avoids
    // any allocation for a channel/user already being tracked.
    // Keyed by lowercase channel so insert (here) and removal (forget_chatter)
    // always match, even if the ircd ever varies the channel's case.
    fn chatter_entry(&mut self, channel: &str, from: &str) -> &mut ChatterState {
        self.chatter
            .entry(channel.to_ascii_lowercase())
            .or_default()
            .entry(from.to_string())
            .or_default()
    }

    // Drop a user's chatter counters for a channel (on part), and the channel's
    // bucket once empty, so kicker state never outlives the people it tracks.
    pub(crate) fn forget_chatter(&mut self, channel: &str, uid: &str) {
        let channel = channel.to_ascii_lowercase();
        if let Some(bucket) = self.chatter.get_mut(&channel) {
            bucket.remove(uid);
            if bucket.is_empty() {
                self.chatter.remove(&channel);
            }
        }
    }

    // Drop a user's chatter counters across every channel (on quit).
    pub(crate) fn forget_chatter_everywhere(&mut self, uid: &str) {
        self.chatter.retain(|_, bucket| {
            bucket.remove(uid);
            !bucket.is_empty()
        });
    }

    // Community moderation: `!votekick <nick>` / `!voteban <nick>`. Each voter
    // (by uid) counts once; when the channel's VOTEKICK threshold is reached the
    // assigned bot kicks (or bans then kicks) the target. Returns None if the line
    // isn't a vote command, so the caller can fall through to fantasy.
    pub(crate) fn handle_vote(&mut self, from: &str, channel: &str, text: &str) -> Option<Vec<NetAction>> {
        let (ban, target_raw) = if let Some(t) = text.strip_prefix("!votekick ") {
            (false, t)
        } else {
            (true, text.strip_prefix("!voteban ")?)
        };
        let target_nick = target_raw.trim();
        if target_nick.is_empty() || target_nick.contains(' ') {
            return None; // not a real vote — let the line reach the flood/badword kicker
        }
        let threshold = self.db.channel(channel).map(|c| c.kickers.votekick).unwrap_or(0);
        let botnick = self.db.channel(channel).and_then(|c| c.assigned_bot.clone());
        let (Some(botnick), true) = (botnick, threshold > 0) else { return None };
        let botuid = self.network.uid_by_nick(&botnick).map(str::to_string)?;
        let Some(target_uid) = self.network.uid_by_nick(target_nick).map(str::to_string) else {
            return None; // unknown target: treat as ordinary text so the bot can't be spammed into flooding, and the flood kicker still sees it
        };
        // Only a current member can be voted out — otherwise `!voteban <online nick
        // from another channel>` would ban someone who never visited.
        if !self.network.channel_members(channel).any(|u| u == target_uid.as_str()) {
            return None;
        }
        let target_display = self.network.nick_of(&target_uid).unwrap_or(target_nick).to_string();
        // Never let the community vote out a service bot, an oper, or a user with
        // channel op-access — moderation authority isn't a valid vote target.
        let target_account = self.network.account_of(&target_uid).map(str::to_string);
        let is_bot = self.bot_uids.values().any(|b| b == &target_uid);
        let is_oper = target_account.as_deref().is_some_and(|a| self.oper_privs(a).any());
        let is_chanop = target_account.as_deref().is_some_and(|a| self.db.channel(channel).is_some_and(|c| c.is_op(a)));
        if is_bot || is_oper || is_chanop {
            return Some(vec![NetAction::Privmsg { from: botuid.clone(), to: channel.to_string(), text: format!("\x02{target_display}\x02 can't be voted out.") }]);
        }
        let now = self.now_secs();
        let key = (channel.to_ascii_lowercase(), target_display.to_ascii_lowercase());

        // Sweep tallies past their window before touching the map: a passed vote
        // deletes its own key, but one that never reaches threshold would linger
        // forever otherwise, so the map would grow without bound under abuse.
        self.votes.retain(|_, vs| now.saturating_sub(vs.started) <= VOTE_TTL);

        let vs = self.votes.entry(key.clone()).or_insert(VoteState { ban, voters: std::collections::HashSet::new(), started: now });
        vs.ban = ban;
        if !vs.voters.insert(from.to_string()) {
            // Already counted this voter: don't re-announce (which let one user spam
            // the bot into flooding), and let the line fall through to the flood kicker.
            return None;
        }
        let count = vs.voters.len() as u16;

        if count < threshold {
            let verb = if ban { "ban" } else { "kick" };
            return Some(vec![NetAction::Privmsg { from: botuid, to: channel.to_string(), text: format!("\x02{count}\x02/\x02{threshold}\x02 votes to {verb} \x02{target_display}\x02.") }]);
        }
        self.votes.remove(&key);
        self.bump("botserv.votekick");
        let mut out = Vec::new();
        if ban {
            if let Some(host) = self.network.host_of(&target_uid).map(str::to_string) {
                out.push(NetAction::ChannelMode { from: botuid.clone(), channel: channel.to_string(), modes: format!("+b *!*@{host}") });
            }
        }
        let verb = if ban { "banned" } else { "kicked" };
        out.push(NetAction::Privmsg { from: botuid.clone(), to: channel.to_string(), text: format!("Vote passed — \x02{target_display}\x02 has been {verb}.") });
        out.push(NetAction::Kick { from: botuid, channel: channel.to_string(), uid: target_uid, reason: format!("Voted out by the channel ({count} votes)") });
        Some(out)
    }
}
