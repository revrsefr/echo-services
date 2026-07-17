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
            // A services ignore silences a user's commands entirely — but an oper
            // can never be ignored (else they could lock themselves out).
            if !privs.any() {
                let host = self.network.host_of(from).unwrap_or("").to_string();
                if self.db.is_ignored(&nick, &host) {
                    return Vec::new();
                }
            }
            let mut matched: Option<String> = None;
            {
                let Self { services, network, db, .. } = self;
                for svc in services.iter_mut() {
                    if to.eq_ignore_ascii_case(svc.uid()) || to.eq_ignore_ascii_case(svc.nick()) {
                        let args: Vec<&str> = text.split_whitespace().collect();
                        svc.on_command(&sender, &args, &mut ctx, network, db);
                        matched = Some(svc.nick().to_ascii_lowercase());
                        break;
                    }
                }
            }
            if let Some(nick) = matched {
                self.bump(&format!("{nick}.command"));
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
        out
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
