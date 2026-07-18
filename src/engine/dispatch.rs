use super::*;

impl Engine {
    // Route a PRIVMSG addressed to a service (by uid or nick) into that service,
    // handing it the sender's resolved nick, login state, and the account store.
    pub(crate) fn dispatch(&mut self, from: &str, to: &str, text: &str) -> Vec<NetAction> {
        let nick = self.network.nick_of(from).unwrap_or(from).to_string();
        let account = self.network.account_of(from).map(str::to_string);
        let privs = account.as_deref().map(|a| self.oper_privs(a)).unwrap_or_default();
        let mut ctx = ServiceCtx::default();
        // Mark the log so we can tell exactly which events this command appends.
        let audit_mark = self.db.log_len();
        let sender = Sender { uid: from, nick: &nick, account: account.as_deref(), privs };
        if to.starts_with('#') || to.starts_with('&') {
            // A community !votekick/!voteban is handled on its own; otherwise the
            // line runs through fantasy (!op …), the kickers, and triggers.
            if let Some(vote_actions) = self.handle_vote(from, to, text) {
                ctx.actions.extend(vote_actions);
            } else {
                self.fantasy(&sender, to, text, &mut ctx);
                let kicks = self.kicker_check(from, to, text);
                let kicked = kicks.iter().any(|a| matches!(a, NetAction::Kick { .. }));
                ctx.actions.extend(kicks);
                // Don't reward a line the bot just kicked for with a response.
                if !kicked {
                    if let Some(resp) = self.trigger_response(from, to, text) {
                        ctx.actions.push(resp);
                    }
                }
            }
            // Record activity in bot channels (surfaced by StatServ).
            if self.db.channel(to).is_some_and(|c| c.assigned_bot.is_some()) {
                self.network.record_line(to, &nick, text);
                self.bump("botserv.messages");
            }
        } else {
            // A services ignore silences a user's commands entirely, and flood
            // control clamps a bot spamming a service in a loop — but an oper is
            // exempt from both (else they could lock themselves out).
            if !privs.any() {
                let host = self.network.host_of(from).unwrap_or("").to_string();
                if self.db.is_ignored(&nick, &host) {
                    return Vec::new();
                }
                // Flood control targets the stated vector: a bot that connects and
                // spams a service in a loop without ever logging in. Identified users
                // are accountable and legitimately burst (channel setup), and the
                // ircd's own fakelag still governs everyone — so only anonymous
                // senders are clamped, and only on lines aimed at one of our services.
                if account.is_none() {
                    let target = self.services.iter()
                        .find(|s| to.eq_ignore_ascii_case(s.uid()) || to.eq_ignore_ascii_case(s.nick()))
                        .map(|s| s.uid().to_string());
                    if let Some(svc_uid) = target {
                        match self.cmd_limiter.check(&host) {
                            CmdVerdict::Allow => {}
                            CmdVerdict::Warn => {
                                let mut out = vec![NetAction::Notice {
                                    from: svc_uid,
                                    to: from.to_string(),
                                    text: "You're sending commands too fast. Slow down and try again in a moment.".to_string(),
                                }];
                                self.apply_msg_style(&mut out);
                                return out;
                            }
                            CmdVerdict::Drop => return Vec::new(),
                        }
                    }
                }
            }
            let mut matched: Option<String> = None;
            {
                let Self { services, network, db, .. } = self;
                for svc in services.iter_mut() {
                    if to.eq_ignore_ascii_case(svc.uid()) || to.eq_ignore_ascii_case(svc.nick()) {
                        let args: Vec<&str> = text.split_whitespace().collect();
                        svc.on_command(&sender, &args, &mut ctx, network, db);
                        matched = Some(svc.nick().to_string()); // real case, for the feed line
                        break;
                    }
                }
            }
            if let Some(nick) = matched {
                self.bump(&format!("{}.command", nick.to_ascii_lowercase()));
                // NOTIFY watch on services use: log the service + verb only (never
                // the arguments, which may carry a password), as "Service:verb". A
                // SET command carries the 'S' flag, everything else 's'.
                let verb = text.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
                let flag = if verb == "set" { 'S' } else { 's' };
                if let Some(line) = self.notify_line(flag, from, None, &format!("used {nick}:{verb}")) {
                    ctx.actions.push(line);
                }
            }
        }
        // Fold any counters the command recorded into the shared registry.
        for key in std::mem::take(&mut ctx.stats) {
            self.bump(&key);
        }
        // A command may have changed the bot registry (BotServ BOT ADD/DEL).
        let mut out = ctx.actions;
        out.extend(self.reconcile_bots());
        // Announce whatever this command changed to the staff audit channel.
        out.extend(self.audit_feed(audit_mark, &nick, account.as_deref()));
        self.apply_dict_limit(&mut out);
        self.apply_msg_style(&mut out);
        out
    }

    // Drop DICT lookups that exceed the global rate budget, so a burst of !dict
    // can't hammer the dictionary server. Non-lookup actions pass untouched, and
    // the limiter is only consulted when a lookup is actually present.
    fn apply_dict_limit(&mut self, out: &mut Vec<NetAction>) {
        if out.iter().any(|a| matches!(a, NetAction::DictLookup { .. })) {
            out.retain(|a| !matches!(a, NetAction::DictLookup { .. }) || self.dict_limiter.allow());
        }
    }

    // Rewrite each service→user NOTICE to a server-notice (sourced from our
    // server) for users who opted into SET SNOTICE; everyone else keeps a normal
    // notice from the pseudoclient. A multi-line reply names the service once, on
    // its first line ("*** NickServ: …"), and the rest are plain "*** …"
    // continuations — so a long HELP isn't the service name on every row. Per
    // target, so notices to channels or to users who didn't opt in are untouched.
    fn apply_msg_style(&self, out: &mut [NetAction]) {
        let mut named: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
        for a in out.iter_mut() {
            let NetAction::Notice { from, to, text } = a else { continue };
            let Some(account) = self.network.account_of(to) else { continue };
            if !self.db.account_wants_snotice(account) {
                continue;
            }
            let Some(nick) = self.services.iter().find(|s| s.uid() == *from).map(|s| s.nick().to_string()) else { continue };
            *text = if named.insert((from.clone(), to.clone())) {
                format!("*** {nick}: {text}")
            } else {
                format!("*** {text}")
            };
            *from = self.sid.clone();
        }
    }

    // fantasy word becomes the command and the channel is injected as its first
    // argument — then re-source the resulting actions from the bot, so the bot is
    // the visible actor.
    fn fantasy(&mut self, sender: &Sender, chan: &str, text: &str, ctx: &mut ServiceCtx) {
        let Some(rest) = text.strip_prefix(FANTASY_PREFIX) else { return };
        let mut words = rest.split_whitespace();
        let Some(cmd) = words.next() else { return };
        // Fantasy only works through an assigned, live bot.
        let Some(botnick) = self.db.channel(chan).and_then(|c| c.assigned_bot.clone()) else { return };
        let Some(botuid) = self.network.uid_by_nick(&botnick).map(str::to_string) else { return };

        // A dice command (!roll/!calc/…) goes to DiceServ, if it's loaded, and its
        // reply is spoken into the channel by the bot; everything else is a channel
        // command handled by ChanServ.
        if matches!(cmd.to_ascii_uppercase().as_str(), "ROLL" | "CALC" | "EXROLL" | "EXCALC") {
            let Some(dsuid) = self.service_uid("DiceServ") else { return };
            let mark = ctx.actions.len();
            let args: Vec<&str> = std::iter::once(cmd).chain(words).collect();
            self.route_to(&dsuid, sender, &args, ctx);
            // Turn DiceServ's private notices into the bot speaking to the channel.
            for a in ctx.actions[mark..].iter_mut() {
                if let NetAction::Notice { text, .. } = a {
                    *a = NetAction::Privmsg { from: botuid.clone(), to: chan.to_string(), text: std::mem::take(text) };
                }
            }
            return;
        }

        // A dictionary command (!dict/!define/…) becomes a deferred DICT lookup the
        // assigned bot speaks — only when DictServ is loaded. The rate limiter in
        // dispatch() drops excess lookups so nobody can hammer the DICT server.
        if let Some(l) = echo_dictserv::lookup_for(cmd) {
            if self.service_uid("DictServ").is_some() {
                let query = words.collect::<Vec<_>>().join(" ");
                if !query.trim().is_empty() {
                    ctx.dict_lookup(botuid.as_str(), chan, l.database, l.label, query);
                }
            }
            return;
        }

        let Some(csuid) = self.service_uid("ChanServ") else { return };
        // Rewrite `!cmd args…` into `CMD #channel args…` for ChanServ.
        let mark = ctx.actions.len();
        let args: Vec<&str> = [cmd, chan].into_iter().chain(words).collect();
        self.route_to(&csuid, sender, &args, ctx);
        // Fantasy is public: the bot speaks ChanServ's text replies into the channel,
        // and its actions (modes, kicks) are re-sourced from the bot.
        for a in ctx.actions[mark..].iter_mut() {
            match a {
                NetAction::Notice { text, .. } => {
                    *a = NetAction::Privmsg { from: botuid.clone(), to: chan.to_string(), text: std::mem::take(text) };
                }
                _ => resource_action(a, &csuid, &botuid),
            }
        }
    }

    // The uid of a loaded service by nick, if present.
    fn service_uid(&self, nick: &str) -> Option<String> {
        self.services.iter().find(|s| s.nick().eq_ignore_ascii_case(nick)).map(|s| s.uid().to_string())
    }

    // Dispatch a command to a specific service (by uid), borrowing the disjoint
    // engine fields it needs.
    fn route_to(&mut self, uid: &str, sender: &Sender, args: &[&str], ctx: &mut ServiceCtx) {
        let Self { services, network, db, .. } = self;
        if let Some(svc) = services.iter_mut().find(|s| s.uid() == uid) {
            svc.on_command(sender, args, ctx, network, db);
        }
    }
}
