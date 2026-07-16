use super::*;

impl Db {
    /// Register `name` to `founder` (an account name).
    pub fn register_channel(&mut self, name: &str, founder: &str) -> Result<(), ChanError> {
        let k = key(name);
        if self.channels.contains_key(&k) {
            return Err(ChanError::Exists);
        }
        let ts = now();
        self.log
            .append(Event::ChannelRegistered { name: name.to_string(), founder: founder.to_string(), ts })
            .map_err(|_| ChanError::Internal)?;
        self.channels.insert(k, ChannelInfo { name: name.to_string(), founder: founder.to_string(), ts, lock_on: String::new(), lock_off: String::new(), access: Vec::new(), akick: Vec::new(), successor: None, desc: String::new(), entrymsg: String::new(), settings: ChanSettings::default(), topic: String::new(), suspension: None, assigned_bot: None , kickers: KickerSettings::default() , badwords: Vec::new(), badwords_rev: 0 , triggers: Vec::new(), triggers_rev: 0, last_used: ts, noexpire: false, expiry_warned: false, oper_note: None });
        Ok(())
    }

    /// The registration for `name`, if any.
    pub fn channel(&self, name: &str) -> Option<&ChannelInfo> {
        self.channels.get(&key(name))
    }

    /// The account record for `name` (its canonical casing), if registered.
    pub fn account(&self, name: &str) -> Option<&Account> {
        self.accounts.get(&key(name))
    }

    /// All registered channels, for listing.
    pub fn channels(&self) -> impl Iterator<Item = &ChannelInfo> {
        self.channels.values()
    }

    /// All registered accounts, for a directory snapshot (see the gRPC layer).
    pub fn accounts(&self) -> impl Iterator<Item = &Account> {
        self.accounts.values()
    }

    /// Names of channels founded by `account` (case-insensitive).
    pub fn channels_owned_by(&self, account: &str) -> Vec<String> {
        self.channels
            .values()
            .filter(|c| c.founder.eq_ignore_ascii_case(account))
            .map(|c| c.name.clone())
            .collect()
    }

    /// Set the mode-lock (chars to keep set / unset) for a registered channel.
    pub fn set_mlock(&mut self, name: &str, on: &str, off: &str) -> Result<(), ChanError> {
        let k = key(name);
        if !self.channels.contains_key(&k) {
            return Err(ChanError::NoChannel);
        }
        self.log
            .append(Event::ChannelMlock { name: name.to_string(), on: on.to_string(), off: off.to_string() })
            .map_err(|_| ChanError::Internal)?;
        let c = self.channels.get_mut(&k).unwrap();
        c.lock_on = on.to_string();
        c.lock_off = off.to_string();
        Ok(())
    }

    /// Grant `account` a level ("op"/"voice") on `channel`.
    pub fn access_add(&mut self, channel: &str, account: &str, level: &str) -> Result<(), ChanError> {
        let k = key(channel);
        if !self.channels.contains_key(&k) {
            return Err(ChanError::NoChannel);
        }
        self.log
            .append(Event::ChannelAccessAdd { channel: channel.to_string(), account: account.to_string(), level: level.to_string() })
            .map_err(|_| ChanError::Internal)?;
        let c = self.channels.get_mut(&k).unwrap();
        c.access.retain(|a| !a.account.eq_ignore_ascii_case(account));
        c.access.push(ChanAccess { account: account.to_string(), level: level.to_string() });
        Ok(())
    }

    /// Remove `account` from `channel`'s access list. Ok(false) if not present.
    pub fn access_del(&mut self, channel: &str, account: &str) -> Result<bool, ChanError> {
        let k = key(channel);
        let Some(c) = self.channels.get(&k) else {
            return Err(ChanError::NoChannel);
        };
        if !c.access.iter().any(|a| a.account.eq_ignore_ascii_case(account)) {
            return Ok(false);
        }
        self.log
            .append(Event::ChannelAccessDel { channel: channel.to_string(), account: account.to_string() })
            .map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().access.retain(|a| !a.account.eq_ignore_ascii_case(account));
        Ok(true)
    }

    /// Add an auto-kick `mask` (with `reason`) to `channel`.
    pub fn akick_add(&mut self, channel: &str, mask: &str, reason: &str) -> Result<(), ChanError> {
        let k = key(channel);
        if !self.channels.contains_key(&k) {
            return Err(ChanError::NoChannel);
        }
        self.log
            .append(Event::ChannelAkickAdd { channel: channel.to_string(), mask: mask.to_string(), reason: reason.to_string() })
            .map_err(|_| ChanError::Internal)?;
        let c = self.channels.get_mut(&k).unwrap();
        c.akick.retain(|a| !a.mask.eq_ignore_ascii_case(mask));
        c.akick.push(ChanAkick { mask: mask.to_string(), reason: reason.to_string() });
        Ok(())
    }

    /// Remove auto-kick `mask` from `channel`. Ok(false) if not present.
    pub fn akick_del(&mut self, channel: &str, mask: &str) -> Result<bool, ChanError> {
        let k = key(channel);
        let Some(c) = self.channels.get(&k) else {
            return Err(ChanError::NoChannel);
        };
        if !c.akick.iter().any(|a| a.mask.eq_ignore_ascii_case(mask)) {
            return Ok(false);
        }
        self.log
            .append(Event::ChannelAkickDel { channel: channel.to_string(), mask: mask.to_string() })
            .map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().akick.retain(|a| !a.mask.eq_ignore_ascii_case(mask));
        Ok(true)
    }

    /// Transfer `channel`'s founder to `account`.
    pub fn set_founder(&mut self, channel: &str, account: &str) -> Result<(), ChanError> {
        let k = key(channel);
        if !self.channels.contains_key(&k) {
            return Err(ChanError::NoChannel);
        }
        self.log
            .append(Event::ChannelFounderSet { channel: channel.to_string(), founder: account.to_string() })
            .map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().founder = account.to_string();
        Ok(())
    }

    /// Set (or clear, with None) `channel`'s successor account.
    pub fn set_successor(&mut self, channel: &str, successor: Option<&str>) -> Result<(), ChanError> {
        let k = key(channel);
        if !self.channels.contains_key(&k) {
            return Err(ChanError::NoChannel);
        }
        let successor = successor.map(|s| s.to_string());
        self.log
            .append(Event::ChannelSuccessorSet { channel: channel.to_string(), successor: successor.clone() })
            .map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().successor = successor;
        Ok(())
    }

    /// The successor account set on `channel`, if any.
    pub fn channel_successor(&self, channel: &str) -> Option<String> {
        self.channels.get(&key(channel)).and_then(|c| c.successor.clone())
    }

    /// Release the channels founded by `account` because the account is going
    /// away: one with a valid successor is transferred to them, the rest are
    /// dropped. Returns (transferred as (channel, successor), dropped channels).
    pub fn release_founded_channels(&mut self, account: &str) -> (Vec<(String, String)>, Vec<String>) {
        let (mut transferred, mut dropped) = (Vec::new(), Vec::new());
        for chan in self.channels_owned_by(account) {
            let successor = self.channel_successor(&chan).filter(|s| !s.eq_ignore_ascii_case(account) && self.exists(s));
            match successor {
                Some(s) if self.set_founder(&chan, &s).is_ok() => {
                    let _ = self.set_successor(&chan, None); // consumed
                    transferred.push((chan, s));
                }
                _ => {
                    let _ = self.drop_channel(&chan);
                    dropped.push(chan);
                }
            }
        }
        (transferred, dropped)
    }

    /// Set `channel`'s description (empty clears it).
    pub fn set_desc(&mut self, channel: &str, desc: &str) -> Result<(), ChanError> {
        let k = key(channel);
        if !self.channels.contains_key(&k) {
            return Err(ChanError::NoChannel);
        }
        self.log
            .append(Event::ChannelDescSet { channel: channel.to_string(), desc: desc.to_string() })
            .map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().desc = desc.to_string();
        Ok(())
    }

    /// Turn one ChanServ SET option on or off for a channel.
    pub fn set_channel_setting(&mut self, channel: &str, setting: ChanSetting, on: bool) -> Result<(), ChanError> {
        let k = key(channel);
        let Some(c) = self.channels.get(&k) else { return Err(ChanError::NoChannel) };
        let mut settings = c.settings;
        match setting {
            ChanSetting::SignKick => settings.signkick = on,
            ChanSetting::Private => settings.private = on,
            ChanSetting::Peace => settings.peace = on,
            ChanSetting::SecureOps => settings.secureops = on,
            ChanSetting::Restricted => settings.restricted = on,
            ChanSetting::AutoOp => settings.noautoop = !on, // stored inverted (default on)
            ChanSetting::KeepTopic => settings.keeptopic = on,
            ChanSetting::TopicLock => settings.topiclock = on,
            ChanSetting::BotGreet => settings.bot_greet = on,
            ChanSetting::NoBot => settings.nobot = on,
        }
        self.log
            .append(Event::ChannelSettingsSet { channel: channel.to_string(), settings })
            .map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().settings = settings;
        Ok(())
    }

    /// Turn one BotServ kicker on or off. Caps thresholds are set via
    /// `set_caps_kicker`; passing `Kicker::Caps` here only toggles it off.
    pub fn set_kicker(&mut self, channel: &str, kicker: Kicker, on: bool) -> Result<(), ChanError> {
        self.update_kickers(channel, |k| match kicker {
            Kicker::Caps => k.caps = on,
            Kicker::Bolds => k.bolds = on,
            Kicker::Colors => k.colors = on,
            Kicker::Underlines => k.underlines = on,
            Kicker::Reverses => k.reverses = on,
            Kicker::Italics => k.italics = on,
            Kicker::Flood => k.flood = on,
            Kicker::Repeat => k.repeat = on,
            Kicker::Badwords => k.badwords = on,
            Kicker::Warn => k.warn = on,
            Kicker::DontKickOps => k.dontkickops = on,
            Kicker::DontKickVoices => k.dontkickvoices = on,
        })
    }

    /// Enable the caps kicker with its length/percentage thresholds (0 = default).
    pub fn set_caps_kicker(&mut self, channel: &str, caps_min: u16, caps_percent: u16) -> Result<(), ChanError> {
        self.update_kickers(channel, |k| {
            k.caps = true;
            k.caps_min = caps_min;
            k.caps_percent = caps_percent;
        })
    }

    /// Enable the flood kicker with its lines/seconds thresholds (0 = default).
    pub fn set_flood_kicker(&mut self, channel: &str, lines: u16, secs: u16) -> Result<(), ChanError> {
        self.update_kickers(channel, |k| {
            k.flood = true;
            k.flood_lines = lines;
            k.flood_secs = secs;
        })
    }

    /// Enable the repeat kicker with its repeat-count threshold (0 = default).
    pub fn set_repeat_kicker(&mut self, channel: &str, times: u16) -> Result<(), ChanError> {
        self.update_kickers(channel, |k| {
            k.repeat = true;
            k.repeat_times = times;
        })
    }

    /// Kicks-before-ban threshold (0 = never ban, only kick).
    pub fn set_ttb(&mut self, channel: &str, ttb: u16) -> Result<(), ChanError> {
        self.update_kickers(channel, |k| k.ttb = ttb)
    }

    /// How long a kicker ban lasts, in seconds (0 = until removed).
    pub fn set_ban_expire(&mut self, channel: &str, secs: u32) -> Result<(), ChanError> {
        self.update_kickers(channel, |k| k.ban_expire = secs)
    }

    /// Votes needed for a community !votekick/!voteban (0 = disabled).
    pub fn set_votekick(&mut self, channel: &str, votes: u16) -> Result<(), ChanError> {
        self.update_kickers(channel, |k| k.votekick = votes)
    }

    /// Add a badword regex. Validates it compiles within the size limit; returns
    /// Ok(false) if the exact pattern is already present.
    pub fn badword_add(&mut self, channel: &str, pattern: &str) -> Result<bool, ChanError> {
        if regex::RegexBuilder::new(pattern).size_limit(BADWORD_SIZE_LIMIT).build().is_err() {
            return Err(ChanError::InvalidPattern);
        }
        let k = key(channel);
        let Some(c) = self.channels.get(&k) else { return Err(ChanError::NoChannel) };
        if c.badwords.iter().any(|w| w == pattern) {
            return Ok(false);
        }
        let mut list = c.badwords.clone();
        list.push(pattern.to_string());
        self.write_badwords(channel, &k, list)?;
        Ok(true)
    }

    /// Remove a badword by exact pattern. Ok(false) if it wasn't listed.
    pub fn badword_del(&mut self, channel: &str, pattern: &str) -> Result<bool, ChanError> {
        let k = key(channel);
        let Some(c) = self.channels.get(&k) else { return Err(ChanError::NoChannel) };
        if !c.badwords.iter().any(|w| w == pattern) {
            return Ok(false);
        }
        let list: Vec<String> = c.badwords.iter().filter(|w| *w != pattern).cloned().collect();
        self.write_badwords(channel, &k, list)?;
        Ok(true)
    }

    /// Clear all badwords; returns how many were removed.
    pub fn badword_clear(&mut self, channel: &str) -> Result<usize, ChanError> {
        let k = key(channel);
        let Some(c) = self.channels.get(&k) else { return Err(ChanError::NoChannel) };
        let n = c.badwords.len();
        if n > 0 {
            self.write_badwords(channel, &k, Vec::new())?;
        }
        Ok(n)
    }

    pub fn badwords(&self, channel: &str) -> &[String] {
        self.channels.get(&key(channel)).map_or(&[], |c| c.badwords.as_slice())
    }

    /// Add an auto-response trigger. Validates the pattern; Ok(false) if the same
    /// pattern is already present.
    pub fn trigger_add(&mut self, channel: &str, pattern: &str, response: &str, cooldown: u32) -> Result<bool, ChanError> {
        if regex::RegexBuilder::new(pattern).size_limit(BADWORD_SIZE_LIMIT).build().is_err() {
            return Err(ChanError::InvalidPattern);
        }
        let k = key(channel);
        let Some(c) = self.channels.get(&k) else { return Err(ChanError::NoChannel) };
        if c.triggers.iter().any(|t| t.pattern == pattern) {
            return Ok(false);
        }
        let mut list = c.triggers.clone();
        list.push(Trigger { pattern: pattern.to_string(), response: response.to_string(), cooldown });
        self.write_triggers(channel, &k, list)?;
        Ok(true)
    }

    /// Remove the trigger at 1-based `index`. Ok(false) if out of range.
    pub fn trigger_del(&mut self, channel: &str, index: usize) -> Result<bool, ChanError> {
        let k = key(channel);
        let Some(c) = self.channels.get(&k) else { return Err(ChanError::NoChannel) };
        if index == 0 || index > c.triggers.len() {
            return Ok(false);
        }
        let mut list = c.triggers.clone();
        list.remove(index - 1);
        self.write_triggers(channel, &k, list)?;
        Ok(true)
    }

    /// Clear all triggers; returns how many were removed.
    pub fn trigger_clear(&mut self, channel: &str) -> Result<usize, ChanError> {
        let k = key(channel);
        let Some(c) = self.channels.get(&k) else { return Err(ChanError::NoChannel) };
        let n = c.triggers.len();
        if n > 0 {
            self.write_triggers(channel, &k, Vec::new())?;
        }
        Ok(n)
    }

    pub fn triggers(&self, channel: &str) -> &[Trigger] {
        self.channels.get(&key(channel)).map_or(&[], |c| c.triggers.as_slice())
    }

    fn write_triggers(&mut self, channel: &str, k: &str, list: Vec<Trigger>) -> Result<(), ChanError> {
        self.log
            .append(Event::ChannelTriggersSet { channel: channel.to_string(), triggers: list.clone() })
            .map_err(|_| ChanError::Internal)?;
        let c = self.channels.get_mut(k).unwrap();
        c.triggers = list;
        c.triggers_rev = c.triggers_rev.wrapping_add(1);
        Ok(())
    }

    /// Dry-run the content kickers against a line: the reason it would be kicked,
    /// or None. Flood/repeat are stateful/time-based and are not simulated here.
    pub fn kicker_test(&self, channel: &str, text: &str) -> Option<String> {
        let c = self.channels.get(&key(channel))?;
        if let Some(reason) = c.kickers.violation(text) {
            return Some(reason.to_string());
        }
        if c.kickers.badwords && !c.badwords.is_empty() && build_badword_set(&c.badwords).is_match(text) {
            return Some("matches a badword".to_string());
        }
        None
    }

    /// Copy one channel's BotServ configuration — kickers, badwords, greet and
    /// nobot — onto another. Both channels must be registered.
    pub fn copy_bot_config(&mut self, src: &str, dst: &str) -> Result<(), ChanError> {
        let (kickers, badwords, bot_greet, nobot) = {
            let s = self.channels.get(&key(src)).ok_or(ChanError::NoChannel)?;
            (s.kickers.clone(), s.badwords.clone(), s.settings.bot_greet, s.settings.nobot)
        };
        let dk = key(dst);
        if !self.channels.contains_key(&dk) {
            return Err(ChanError::NoChannel);
        }
        self.log.append(Event::ChannelKickerSet { channel: dst.to_string(), kickers: kickers.clone() }).map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&dk).unwrap().kickers = kickers;
        self.write_badwords(dst, &dk, badwords)?;
        self.set_channel_setting(dst, ChanSetting::BotGreet, bot_greet)?;
        self.set_channel_setting(dst, ChanSetting::NoBot, nobot)?;
        Ok(())
    }

    // Persist a new badword list (whole-list event) and apply it.
    fn write_badwords(&mut self, channel: &str, k: &str, list: Vec<String>) -> Result<(), ChanError> {
        self.log
            .append(Event::ChannelBadwordsSet { channel: channel.to_string(), badwords: list.clone() })
            .map_err(|_| ChanError::Internal)?;
        let c = self.channels.get_mut(k).unwrap();
        c.badwords = list;
        c.badwords_rev = c.badwords_rev.wrapping_add(1);
        Ok(())
    }

    // Read-modify-write the whole kicker struct through one event.
    fn update_kickers(&mut self, channel: &str, f: impl FnOnce(&mut KickerSettings)) -> Result<(), ChanError> {
        let k = key(channel);
        let Some(c) = self.channels.get(&k) else { return Err(ChanError::NoChannel) };
        let mut kickers = c.kickers.clone();
        f(&mut kickers);
        self.log
            .append(Event::ChannelKickerSet { channel: channel.to_string(), kickers: kickers.clone() })
            .map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().kickers = kickers;
        Ok(())
    }

    /// Remember a channel's topic (KEEPTOPIC / TOPICLOCK).
    pub fn set_channel_topic(&mut self, channel: &str, topic: &str) -> Result<(), ChanError> {
        let k = key(channel);
        if !self.channels.contains_key(&k) {
            return Err(ChanError::NoChannel);
        }
        self.log
            .append(Event::ChannelTopicSet { channel: channel.to_string(), topic: topic.to_string() })
            .map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().topic = topic.to_string();
        Ok(())
    }

    /// Suspend a channel. `expires` is absolute unix time (None = permanent).
    pub fn suspend_channel(&mut self, channel: &str, by: &str, reason: &str, expires: Option<u64>) -> Result<(), ChanError> {
        let k = key(channel);
        if !self.channels.contains_key(&k) {
            return Err(ChanError::NoChannel);
        }
        let ts = now();
        self.log.append(Event::ChannelSuspended { channel: channel.to_string(), by: by.to_string(), reason: reason.to_string(), ts, expires }).map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().suspension = Some(Suspension { by: by.to_string(), reason: reason.to_string(), ts, expires });
        Ok(())
    }

    /// Lift a channel suspension. Returns whether one was set.
    pub fn unsuspend_channel(&mut self, channel: &str) -> Result<bool, ChanError> {
        let k = key(channel);
        match self.channels.get(&k) {
            None => return Err(ChanError::NoChannel),
            Some(c) if c.suspension.is_none() => return Ok(false),
            Some(_) => {}
        }
        self.log.append(Event::ChannelUnsuspended { channel: channel.to_string() }).map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().suspension = None;
        Ok(true)
    }

    /// Whether a channel has a set, unexpired suspension (lazy — no timer).
    pub fn is_channel_suspended(&self, channel: &str) -> bool {
        self.channels.get(&key(channel)).and_then(|c| c.suspension.as_ref()).is_some_and(|s| s.expires.is_none_or(|e| e > now()))
    }

    /// The channel's suspension record, if any.
    pub fn channel_suspension(&self, channel: &str) -> Option<SuspensionView> {
        self.channels.get(&key(channel)).and_then(|c| c.suspension.as_ref()).map(|s| SuspensionView { by: s.by.clone(), reason: s.reason.clone(), ts: s.ts, expires: s.expires })
    }

    /// Register a service bot.
    pub fn bot_add(&mut self, nick: &str, user: &str, host: &str, gecos: &str) -> Result<(), ChanError> {
        let k = key(nick);
        if self.bots.contains_key(&k) {
            return Err(ChanError::Exists);
        }
        let bot = Bot { nick: nick.to_string(), user: user.to_string(), host: host.to_string(), gecos: gecos.to_string(), private: false };
        self.log.append(Event::BotAdded(bot.clone())).map_err(|_| ChanError::Internal)?;
        self.bots.insert(k, bot);
        Ok(())
    }

    /// Mark a bot private (oper-only assign) or public. Returns Ok(false) if
    /// there is no such bot.
    pub fn bot_set_private(&mut self, nick: &str, private: bool) -> Result<bool, ChanError> {
        let k = key(nick);
        let Some(mut bot) = self.bots.get(&k).cloned() else { return Ok(false) };
        bot.private = private;
        self.log.append(Event::BotAdded(bot.clone())).map_err(|_| ChanError::Internal)?;
        self.bots.insert(k, bot);
        Ok(true)
    }

    /// Delete every service bot at once (BOT DEL *). Returns how many went.
    pub fn bot_del_all(&mut self) -> Result<usize, ChanError> {
        let nicks: Vec<String> = self.bots.values().map(|b| b.nick.clone()).collect();
        for n in &nicks {
            self.log.append(Event::BotRemoved { nick: n.clone() }).map_err(|_| ChanError::Internal)?;
        }
        self.bots.clear();
        Ok(nicks.len())
    }

    /// Delete a service bot. Returns whether it existed.
    pub fn bot_del(&mut self, nick: &str) -> Result<bool, ChanError> {
        let k = key(nick);
        if !self.bots.contains_key(&k) {
            return Ok(false);
        }
        self.log.append(Event::BotRemoved { nick: nick.to_string() }).map_err(|_| ChanError::Internal)?;
        self.bots.remove(&k);
        Ok(true)
    }

    /// Change a bot's nick and/or identity. `NoChannel` = no such bot,
    /// `Exists` = the new nick belongs to a different bot. On a rename, every
    /// channel the old bot was assigned to is moved to the new nick.
    pub fn bot_change(&mut self, old: &str, new_nick: &str, user: &str, host: &str, gecos: &str) -> Result<(), ChanError> {
        let ok = key(old);
        if !self.bots.contains_key(&ok) {
            return Err(ChanError::NoChannel);
        }
        let nk = key(new_nick);
        let renaming = ok != nk;
        if renaming && self.bots.contains_key(&nk) {
            return Err(ChanError::Exists);
        }
        // Keep the private flag across a change.
        let private = self.bots.get(&ok).map(|b| b.private).unwrap_or(false);
        let bot = Bot { nick: new_nick.to_string(), user: user.to_string(), host: host.to_string(), gecos: gecos.to_string(), private };
        if renaming {
            let chans: Vec<String> = self
                .channels
                .values()
                .filter(|c| c.assigned_bot.as_deref().is_some_and(|b| key(b) == ok))
                .map(|c| c.name.clone())
                .collect();
            self.log.append(Event::BotRemoved { nick: old.to_string() }).map_err(|_| ChanError::Internal)?;
            self.bots.remove(&ok);
            self.log.append(Event::BotAdded(bot.clone())).map_err(|_| ChanError::Internal)?;
            self.bots.insert(nk, bot);
            for chan in chans {
                self.log.append(Event::ChannelBotAssigned { channel: chan.clone(), bot: new_nick.to_string() }).map_err(|_| ChanError::Internal)?;
                self.channels.get_mut(&key(&chan)).unwrap().assigned_bot = Some(new_nick.to_string());
            }
        } else {
            // Same nick, new identity: re-emit BotAdded to overwrite the fields.
            self.log.append(Event::BotAdded(bot.clone())).map_err(|_| ChanError::Internal)?;
            self.bots.insert(nk, bot);
        }
        Ok(())
    }

    /// All registered bots.
    pub fn bots(&self) -> impl Iterator<Item = &Bot> {
        self.bots.values()
    }

    /// The bot auto-assigned to newly registered channels, if one is set and
    /// still exists (its canonical nick).
    pub fn default_bot(&self) -> Option<&str> {
        let k = self.net.default_bot.as_ref()?;
        self.bots.get(k).map(|b| b.nick.as_str())
    }

    /// Set (or clear) the auto-assign bot. The caller validates the bot exists;
    /// the nick is stored casefolded.
    pub fn set_default_bot(&mut self, bot: Option<&str>) -> Result<(), ChanError> {
        let stored = bot.map(|b| b.to_string());
        self.log.append(Event::DefaultBotSet { bot: stored.clone() }).map_err(|_| ChanError::Internal)?;
        self.net.default_bot = stored.map(|b| key(&b));
        Ok(())
    }

    /// Assign a bot to a channel.
    pub fn assign_bot(&mut self, channel: &str, bot: &str) -> Result<(), ChanError> {
        let k = key(channel);
        if !self.channels.contains_key(&k) {
            return Err(ChanError::NoChannel);
        }
        self.log.append(Event::ChannelBotAssigned { channel: channel.to_string(), bot: bot.to_string() }).map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().assigned_bot = Some(bot.to_string());
        Ok(())
    }

    /// Unassign a channel's bot. Returns whether one was assigned.
    pub fn unassign_bot(&mut self, channel: &str) -> Result<bool, ChanError> {
        let k = key(channel);
        match self.channels.get(&k) {
            None => return Err(ChanError::NoChannel),
            Some(c) if c.assigned_bot.is_none() => return Ok(false),
            Some(_) => {}
        }
        self.log.append(Event::ChannelBotUnassigned { channel: channel.to_string() }).map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().assigned_bot = None;
        Ok(true)
    }

    /// Append a memo to an account's mailbox.
    pub fn memo_send(&mut self, account: &str, from: &str, text: &str, receipt: bool) -> Result<(), RegError> {
        let k = key(account);
        if !self.accounts.contains_key(&k) {
            return Err(RegError::Internal);
        }
        let ts = now();
        self.log.append(Event::MemoSent { account: account.to_string(), from: from.to_string(), text: text.to_string(), ts, receipt }).map_err(|_| RegError::Internal)?;
        self.accounts.get_mut(&k).unwrap().memos.push(Memo { from: from.to_string(), text: text.to_string(), ts, read: false, receipt });
        Ok(())
    }

    /// An account's memos, oldest first.
    pub fn memo_list(&self, account: &str) -> Vec<MemoView> {
        self.accounts.get(&key(account)).map_or(Vec::new(), |a| {
            a.memos.iter().map(|m| MemoView { from: m.from.clone(), text: m.text.clone(), ts: m.ts, read: m.read, receipt: m.receipt }).collect()
        })
    }

    /// Read one memo by index (marks it read), returning its contents.
    pub fn memo_read(&mut self, account: &str, index: usize) -> Option<MemoView> {
        let k = key(account);
        let view = self.accounts.get(&k).and_then(|a| a.memos.get(index)).map(|m| MemoView { from: m.from.clone(), text: m.text.clone(), ts: m.ts, read: m.read, receipt: m.receipt })?;
        if !view.read {
            let _ = self.log.append(Event::MemoRead { account: account.to_string(), index });
            if let Some(m) = self.accounts.get_mut(&k).and_then(|a| a.memos.get_mut(index)) {
                m.read = true;
            }
        }
        Some(view)
    }

    /// Delete one memo by index. Returns whether it existed.
    pub fn memo_del(&mut self, account: &str, index: usize) -> bool {
        let k = key(account);
        if !self.accounts.get(&k).is_some_and(|a| index < a.memos.len()) {
            return false;
        }
        let _ = self.log.append(Event::MemoDeleted { account: account.to_string(), index });
        if let Some(a) = self.accounts.get_mut(&k) {
            if index < a.memos.len() {
                a.memos.remove(index);
            }
        }
        true
    }

    /// Recall the most recent UNREAD memo `sender` left for `account`. Returns
    /// whether one was cancelled — a memo the recipient already read can't be recalled.
    pub fn memo_cancel(&mut self, account: &str, sender: &str) -> bool {
        let sender_lc = sender.to_ascii_lowercase();
        let idx = self.accounts.get(&key(account)).and_then(|a| {
            a.memos.iter().enumerate().rev().find(|(_, m)| !m.read && m.from.to_ascii_lowercase() == sender_lc).map(|(i, _)| i)
        });
        match idx {
            Some(i) => self.memo_del(account, i),
            None => false,
        }
    }

    /// The read-status and timestamp of the most recent memo `sender` left for
    /// `account`, or None if they have none in that mailbox.
    pub fn memo_check(&self, account: &str, sender: &str) -> Option<(bool, u64)> {
        let sender_lc = sender.to_ascii_lowercase();
        self.accounts.get(&key(account)).and_then(|a| {
            a.memos.iter().rev().find(|m| m.from.to_ascii_lowercase() == sender_lc).map(|m| (m.read, m.ts))
        })
    }

    /// Add `target` to `account`'s memo-ignore list. Returns whether it was new.
    pub fn memo_ignore_add(&mut self, account: &str, target: &str) -> bool {
        let k = key(account);
        let Some(a) = self.accounts.get(&k) else { return false };
        if a.memo_ignore.iter().any(|t| t.eq_ignore_ascii_case(target)) {
            return false;
        }
        let _ = self.log.append(Event::MemoIgnoreAdd { account: account.to_string(), target: target.to_string() });
        self.accounts.get_mut(&k).unwrap().memo_ignore.push(target.to_string());
        true
    }

    /// Remove `target` from `account`'s memo-ignore list. Returns whether it existed.
    pub fn memo_ignore_del(&mut self, account: &str, target: &str) -> bool {
        let k = key(account);
        let Some(a) = self.accounts.get(&k) else { return false };
        if !a.memo_ignore.iter().any(|t| t.eq_ignore_ascii_case(target)) {
            return false;
        }
        let _ = self.log.append(Event::MemoIgnoreDel { account: account.to_string(), target: target.to_string() });
        self.accounts.get_mut(&k).unwrap().memo_ignore.retain(|t| !t.eq_ignore_ascii_case(target));
        true
    }

    /// `account`'s memo-ignore list.
    pub fn memo_ignores(&self, account: &str) -> Vec<String> {
        self.accounts.get(&key(account)).map_or(Vec::new(), |a| a.memo_ignore.clone())
    }

    /// Whether `account` is ignoring memos from `sender`.
    pub fn memo_is_ignored(&self, account: &str, sender: &str) -> bool {
        self.accounts.get(&key(account)).is_some_and(|a| a.memo_ignore.iter().any(|t| t.eq_ignore_ascii_case(sender)))
    }

    /// Set whether `account` is notified about new memos on login.
    pub fn set_memo_notify(&mut self, account: &str, on: bool) -> bool {
        let k = key(account);
        let Some(a) = self.accounts.get(&k) else { return false };
        let limit = a.memo_limit;
        let _ = self.log.append(Event::MemoPrefsSet { account: account.to_string(), notify: on, limit });
        self.accounts.get_mut(&k).unwrap().memo_notify = on;
        true
    }

    /// Set `account`'s mailbox cap (None = the network default).
    pub fn set_memo_limit(&mut self, account: &str, limit: Option<u32>) -> bool {
        let k = key(account);
        let Some(a) = self.accounts.get(&k) else { return false };
        let notify = a.memo_notify;
        let _ = self.log.append(Event::MemoPrefsSet { account: account.to_string(), notify, limit });
        self.accounts.get_mut(&k).unwrap().memo_limit = limit;
        true
    }

    /// Whether `account` wants new-memo notifications (default on / unknown = on).
    pub fn memo_notify_on(&self, account: &str) -> bool {
        self.accounts.get(&key(account)).is_none_or(|a| a.memo_notify)
    }

    /// `account`'s configured mailbox cap, if any.
    pub fn memo_limit_of(&self, account: &str) -> Option<u32> {
        self.accounts.get(&key(account)).and_then(|a| a.memo_limit)
    }

    /// How many unread memos an account has.
    pub fn unread_memos(&self, account: &str) -> usize {
        self.accounts.get(&key(account)).map_or(0, |a| a.memos.iter().filter(|m| !m.read).count())
    }

    /// Set `channel`'s entry message (empty clears it).
    pub fn set_entrymsg(&mut self, channel: &str, msg: &str) -> Result<(), ChanError> {
        let k = key(channel);
        if !self.channels.contains_key(&k) {
            return Err(ChanError::NoChannel);
        }
        self.log
            .append(Event::ChannelEntryMsgSet { channel: channel.to_string(), msg: msg.to_string() })
            .map_err(|_| ChanError::Internal)?;
        self.channels.get_mut(&k).unwrap().entrymsg = msg.to_string();
        Ok(())
    }

    /// Unregister `name`.
    pub fn drop_channel(&mut self, name: &str) -> Result<(), ChanError> {
        let k = key(name);
        if !self.channels.contains_key(&k) {
            return Err(ChanError::NoChannel);
        }
        self.log.append(Event::ChannelDropped { name: name.to_string() }).map_err(|_| ChanError::Internal)?;
        self.channels.remove(&k);
        Ok(())
    }
}
