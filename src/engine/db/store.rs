use super::*;

impl Store for Db {
    fn exists(&self, name: &str) -> bool {
        Db::exists(self, name)
    }
    fn account(&self, name: &str) -> Option<AccountView> {
        Db::account(self, name).map(|a| AccountView {
            name: a.name.clone(),
            email: a.email.clone(),
            ts: a.ts,
            verified: a.verified,
            greet: a.greet.clone(),
            last_seen: a.last_seen,
            hide_status: a.hide_status,
        })
    }
    fn resolve_account(&self, name: &str) -> Option<&str> {
        Db::resolve_account(self, name)
    }
    fn accounts_matching(&self, pattern: &str) -> Vec<AccountView> {
        self.accounts()
            .filter(|a| super::glob_match(pattern, &a.name))
            .map(|a| AccountView { name: a.name.clone(), email: a.email.clone(), ts: a.ts, verified: a.verified, greet: a.greet.clone(), last_seen: a.last_seen, hide_status: a.hide_status })
            .collect()
    }
    fn accounts_by_email(&self, pattern: &str) -> Vec<String> {
        self.accounts()
            .filter(|a| a.email.as_deref().is_some_and(|e| super::glob_match(pattern, e)))
            .map(|a| a.name.clone())
            .collect()
    }
    fn authenticate(&self, name: &str, password: &str) -> Option<&str> {
        Db::authenticate(self, name, password)
    }
    fn scram_verifier(&self, name: &str) -> Option<(String, String)> {
        Db::scram_lookup(self, name, "SCRAM-SHA-256").map(|(a, v)| (a.to_string(), v.to_string()))
    }
    fn grouped_nicks(&self, account: &str) -> Vec<String> {
        Db::grouped_nicks(self, account)
    }
    fn certfps(&self, account: &str) -> &[String] {
        Db::certfps(self, account)
    }
    fn is_verified(&self, account: &str) -> bool {
        Db::is_verified(self, account)
    }
    fn channel(&self, name: &str) -> Option<ChannelView> {
        Db::channel(self, name).map(channel_view)
    }
    fn channels(&self) -> Vec<ChannelView> {
        Db::channels(self).map(channel_view).collect()
    }
    fn channels_owned_by(&self, account: &str) -> Vec<String> {
        Db::channels_owned_by(self, account)
    }
    fn extban_enabled(&self, name: &str) -> bool {
        Db::extban_allowed(self, name)
    }
    fn extban_offered(&self, name: &str) -> bool {
        Db::extban_offered(self, name)
    }
    fn extban_lookup(&self, token: &str) -> Option<echo_api::ExtbanCap> {
        Db::extban_lookup(self, token)
    }
    fn extbans(&self) -> Vec<echo_api::ExtbanCap> {
        Db::extbans(self)
    }
    fn chanmode_takes_param(&self, m: char, adding: bool) -> bool {
        Db::chanmode_takes_param(self, m, adding)
    }
    fn status_modes(&self) -> String {
        Db::status_modes(self)
    }
    fn email_enabled(&self) -> bool {
        Db::email_enabled(self)
    }
    fn email_brand(&self) -> &str {
        Db::email_brand(self)
    }
    fn email_accent(&self) -> &str {
        Db::email_accent(self)
    }
    fn email_logo(&self) -> &str {
        Db::email_logo(self)
    }
    fn issue_code(&mut self, account: &str, kind: CodeKind) -> String {
        Db::issue_code(self, account, kind)
    }
    fn take_code(&mut self, account: &str, kind: CodeKind, code: &str) -> bool {
        Db::take_code(self, account, kind, code)
    }
    fn auth_lockout(&self, account: &str) -> Option<u64> {
        Db::auth_lockout(self, account)
    }
    fn note_auth(&mut self, account: &str, success: bool) {
        Db::note_auth(self, account, success)
    }
    fn verify_account(&mut self, account: &str) -> Result<(), RegError> {
        Db::verify_account(self, account)
    }
    fn set_email(&mut self, account: &str, email: Option<String>) -> Result<(), RegError> {
        Db::set_email(self, account, email)
    }
    fn set_greet(&mut self, account: &str, greet: &str) -> Result<(), RegError> {
        Db::set_greet(self, account, greet)
    }
    fn set_language(&mut self, account: &str, language: Option<String>) -> Result<(), RegError> {
        Db::set_language(self, account, language)
    }
    fn language_of(&self, account: &str) -> Option<String> {
        Db::language_of(self, account)
    }
    fn available_languages(&self) -> Vec<String> {
        Db::available_languages(self).to_vec()
    }
    fn default_language(&self) -> String {
        Db::default_language(self)
    }
    fn set_account_autoop(&mut self, account: &str, on: bool) -> Result<(), RegError> {
        Db::set_account_autoop(self, account, on)
    }
    fn account_wants_autoop(&self, account: &str) -> bool {
        Db::account_wants_autoop(self, account)
    }
    fn set_account_kill(&mut self, account: &str, on: bool) -> Result<(), RegError> {
        Db::set_account_kill(self, account, on)
    }
    fn account_wants_protect(&self, account: &str) -> bool {
        Db::account_wants_protect(self, account)
    }
    fn set_account_hide_status(&mut self, account: &str, on: bool) -> Result<(), RegError> {
        Db::set_account_hide_status(self, account, on)
    }
    fn account_hides_status(&self, account: &str) -> bool {
        Db::account_hides_status(self, account)
    }
    fn set_account_snotice(&mut self, account: &str, on: bool) -> Result<(), RegError> {
        Db::set_account_snotice(self, account, on)
    }
    fn account_wants_snotice(&self, account: &str) -> bool {
        Db::account_wants_snotice(self, account)
    }
    fn set_vhost(&mut self, account: &str, host: &str, setter: &str, ttl: Option<u64>) -> Result<(), RegError> {
        Db::set_vhost(self, account, host, setter, ttl)
    }
    fn del_vhost(&mut self, account: &str) -> Result<bool, RegError> {
        Db::del_vhost(self, account)
    }
    fn vhost(&self, account: &str) -> Option<VhostView> {
        Db::account(self, account).and_then(|a| {
            a.vhost.as_ref().filter(|v| v.expires.is_none_or(|e| e > now())).map(|v| VhostView { account: a.name.clone(), host: v.host.clone(), setter: v.setter.clone(), expires: v.expires })
        })
    }
    fn vhosts(&self) -> Vec<VhostView> {
        Db::vhosts(self).into_iter().map(|(account, host, setter, expires)| VhostView { account, host, setter, expires }).collect()
    }
    fn vhost_owner(&self, host: &str) -> Option<String> {
        Db::vhost_owner(self, host)
    }
    fn request_vhost(&mut self, account: &str, host: &str) -> Result<(), RegError> {
        Db::request_vhost(self, account, host)
    }
    fn vhost_request_wait(&self, account: &str) -> u64 {
        Db::vhost_request_wait(self, account)
    }
    fn code_issue_wait(&self, account: &str) -> u64 {
        Db::code_issue_wait(self, account)
    }
    fn take_vhost_request(&mut self, account: &str) -> Result<Option<String>, RegError> {
        Db::take_vhost_request(self, account)
    }
    fn vhost_requests(&self) -> Vec<(String, String)> {
        Db::vhost_requests(self)
    }
    fn vhost_offer_add(&mut self, host: &str) -> Result<bool, RegError> {
        Db::vhost_offer_add(self, host)
    }
    fn vhost_offer_del(&mut self, index: usize) -> Result<Option<String>, RegError> {
        Db::vhost_offer_del(self, index)
    }
    fn vhost_offers(&self) -> Vec<String> {
        Db::vhost_offers(self).to_vec()
    }
    fn vhost_forbid_add(&mut self, pattern: &str) -> Result<bool, RegError> {
        Db::vhost_forbid_add(self, pattern)
    }
    fn vhost_forbid_del(&mut self, index: usize) -> Result<Option<String>, RegError> {
        Db::vhost_forbid_del(self, index)
    }
    fn vhost_forbidden(&self) -> Vec<String> {
        Db::vhost_forbidden(self).to_vec()
    }
    fn vhost_is_forbidden(&self, host: &str) -> bool {
        Db::vhost_is_forbidden(self, host)
    }
    fn set_vhost_template(&mut self, template: Option<String>) -> Result<(), RegError> {
        Db::set_vhost_template(self, template)
    }
    fn vhost_template(&self) -> Option<String> {
        Db::vhost_template(self).map(str::to_string)
    }
    fn group_nick(&mut self, nick: &str, account: &str) -> Result<(), RegError> {
        Db::group_nick(self, nick, account)
    }
    fn ungroup_nick(&mut self, nick: &str) -> Result<bool, RegError> {
        Db::ungroup_nick(self, nick)
    }
    fn drop_account(&mut self, account: &str) -> Result<bool, RegError> {
        Db::drop_account(self, account)
    }
    fn certfp_add(&mut self, account: &str, fp: &str) -> Result<(), CertError> {
        Db::certfp_add(self, account, fp)
    }
    fn certfp_del(&mut self, account: &str, fp: &str) -> Result<bool, CertError> {
        Db::certfp_del(self, account, fp)
    }
    fn ajoin_list(&self, account: &str) -> Vec<AjoinView> {
        Db::ajoin_list(self, account)
            .iter()
            .map(|e| AjoinView { channel: e.channel.clone(), key: e.key.clone() })
            .collect()
    }
    fn ajoin_add(&mut self, account: &str, channel: &str, key: &str) -> Result<bool, RegError> {
        Db::ajoin_add(self, account, channel, key)
    }
    fn ajoin_del(&mut self, account: &str, channel: &str) -> Result<bool, RegError> {
        Db::ajoin_del(self, account, channel)
    }
    fn suspend_account(&mut self, account: &str, by: &str, reason: &str, expires: Option<u64>) -> Result<(), RegError> {
        Db::suspend_account(self, account, by, reason, expires)
    }
    fn unsuspend_account(&mut self, account: &str) -> Result<bool, RegError> {
        Db::unsuspend_account(self, account)
    }
    fn is_suspended(&self, account: &str) -> bool {
        Db::is_suspended(self, account)
    }
    fn suspension(&self, account: &str) -> Option<SuspensionView> {
        Db::suspension(self, account)
    }
    fn set_account_noexpire(&mut self, account: &str, on: bool) -> Result<bool, RegError> {
        Db::set_account_noexpire(self, account, on)
    }
    fn set_channel_noexpire(&mut self, channel: &str, on: bool) -> Result<bool, ChanError> {
        Db::set_channel_noexpire(self, channel, on)
    }
    fn akill_add(&mut self, kind: XlineKind, mask: &str, setter: &str, reason: &str, expires: Option<u64>) -> Result<bool, RegError> {
        Db::akill_add(self, kind, mask, setter, reason, expires)
    }
    fn akill_del(&mut self, kind: XlineKind, mask: &str) -> Result<bool, RegError> {
        Db::akill_del(self, kind, mask)
    }
    fn akills(&self) -> Vec<AkillView> {
        Db::akills(self)
    }
    fn filter_add(&mut self, pattern: &str, action: &str, flags: &str, setter: &str, reason: &str, expires: Option<u64>) -> Result<bool, RegError> {
        Db::filter_add(self, pattern, action, flags, setter, reason, expires)
    }
    fn filter_del(&mut self, pattern: &str) -> Result<bool, RegError> {
        Db::filter_del(self, pattern)
    }
    fn filters(&self) -> Vec<echo_api::FilterView> {
        Db::filters(self)
    }
    fn forbid_add(&mut self, kind: ForbidKind, mask: &str, setter: &str, reason: &str) -> Result<bool, RegError> {
        Db::forbid_add(self, kind, mask, setter, reason)
    }
    fn forbid_del(&mut self, kind: ForbidKind, mask: &str) -> Result<bool, RegError> {
        Db::forbid_del(self, kind, mask)
    }
    fn forbids(&self) -> Vec<ForbidView> {
        Db::forbids(self)
    }
    fn is_forbidden(&self, kind: ForbidKind, name: &str) -> Option<String> {
        Db::is_forbidden(self, kind, name)
    }
    fn notify_add(&mut self, mask: &str, flags: &str, reason: &str, setter: &str, expires: Option<u64>) -> Result<bool, RegError> {
        Db::notify_add(self, mask, flags, reason, setter, expires)
    }
    fn notify_del(&mut self, mask: &str) -> Result<bool, RegError> {
        Db::notify_del(self, mask)
    }
    fn notify_clear(&mut self) -> Result<usize, RegError> {
        Db::notify_clear(self)
    }
    fn notifies(&self) -> Vec<NotifyView> {
        Db::notifies(self)
    }
    fn any_notifies(&self) -> bool {
        Db::any_notifies(self)
    }
    fn notify_flags(&self, target: Option<&echo_api::BanTarget>, chan: Option<&str>) -> String {
        Db::notify_flags(self, target, chan)
    }
    fn ignore_add(&mut self, mask: &str, reason: &str, expires: Option<u64>) {
        Db::ignore_add(self, mask, reason, expires)
    }
    fn ignore_del(&mut self, mask: &str) -> bool {
        Db::ignore_del(self, mask)
    }
    fn ignores(&self) -> Vec<IgnoreView> {
        Db::ignores(self)
    }
    fn jupe_add(&mut self, name: &str, reason: &str) -> String {
        Db::jupe_add(self, name, reason)
    }
    fn jupe_del(&mut self, name: &str) -> Option<String> {
        Db::jupe_del(self, name)
    }
    fn jupes(&self) -> Vec<(String, String, String)> {
        Db::jupes(self)
    }
    fn defcon(&self) -> u8 {
        Db::defcon(self)
    }
    fn set_defcon(&mut self, level: u8) {
        Db::set_defcon(self, level)
    }
    fn readonly(&self) -> bool {
        Db::readonly(self)
    }
    fn set_readonly(&mut self, on: bool) {
        Db::set_readonly(self, on)
    }
    fn registrations_frozen(&self) -> bool {
        Db::registrations_frozen(self)
    }
    fn channel_regs_frozen(&self) -> bool {
        Db::channel_regs_frozen(self)
    }
    fn external_accounts(&self) -> bool {
        Db::external_accounts(self)
    }
    fn confusable_check_enabled(&self) -> bool {
        self.confusable_check
    }
    fn set_account_note(&mut self, account: &str, note: Option<String>) -> bool {
        Db::set_account_note(self, account, note)
    }
    fn account_note(&self, account: &str) -> Option<String> {
        Db::account_note(self, account)
    }
    fn set_channel_note(&mut self, channel: &str, note: Option<String>) -> bool {
        Db::set_channel_note(self, channel, note)
    }
    fn channel_note(&self, channel: &str) -> Option<String> {
        Db::channel_note(self, channel)
    }
    fn news_add(&mut self, kind: NewsKind, text: &str, setter: &str) -> u64 {
        Db::news_add(self, kind, text, setter)
    }
    fn news_del(&mut self, id: u64) -> bool {
        Db::news_del(self, id)
    }
    fn news(&self, kind: NewsKind) -> Vec<NewsView> {
        Db::news(self, kind)
    }
    fn report_file(&mut self, reporter: &str, cooldown_key: &str, target: &str, reason: &str) -> Option<u64> {
        Db::report_file(self, reporter, cooldown_key, target, reason)
    }
    fn report_close(&mut self, id: u64) -> bool {
        Db::report_close(self, id)
    }
    fn report_del(&mut self, id: u64) -> bool {
        Db::report_del(self, id)
    }
    fn reports(&self, open_only: bool) -> Vec<ReportView> {
        Db::reports(self, open_only)
    }
    fn report(&self, id: u64) -> Option<ReportView> {
        Db::report(self, id)
    }
    fn help_request(&mut self, requester: &str, cooldown_key: &str, message: &str) -> Option<u64> {
        Db::help_request(self, requester, cooldown_key, message)
    }
    fn help_take(&mut self, id: u64, handler: &str) -> bool {
        Db::help_take(self, id, handler)
    }
    fn help_close(&mut self, id: u64) -> bool {
        Db::help_close(self, id)
    }
    fn help_tickets(&self, open_only: bool) -> Vec<HelpView> {
        Db::help_tickets(self, open_only)
    }
    fn help_ticket(&self, id: u64) -> Option<HelpView> {
        Db::help_ticket(self, id)
    }
    fn help_next_open(&self) -> Option<u64> {
        Db::help_next_open(self)
    }
    fn group_register(&mut self, name: &str, founder: &str) -> Result<(), ChanError> {
        Db::group_register(self, name, founder)
    }
    fn group_drop(&mut self, name: &str) -> Result<(), ChanError> {
        Db::group_drop(self, name)
    }
    fn group_set_flags(&mut self, name: &str, account: &str, flags: &str) -> Result<(), ChanError> {
        Db::group_set_flags(self, name, account, flags)
    }
    fn group_del_member(&mut self, name: &str, account: &str) -> Result<bool, ChanError> {
        Db::group_del_member(self, name, account)
    }
    fn group_set_founder(&mut self, name: &str, founder: &str) -> Result<(), ChanError> {
        Db::group_set_founder(self, name, founder)
    }
    fn group(&self, name: &str) -> Option<GroupView> {
        Db::group(self, name)
    }
    fn groups(&self) -> Vec<String> {
        Db::groups(self)
    }
    fn groups_of(&self, account: &str) -> Vec<String> {
        Db::groups_of(self, account)
    }
    fn groups_founded(&self, account: &str) -> usize {
        Db::groups_founded(self, account)
    }
    fn channel_caps(&self, channel: &str, account: &str) -> Caps {
        Db::channel_caps(self, channel, account)
    }
    fn oper_grant(&mut self, account: &str, privs: Vec<String>, expires: Option<u64>) {
        Db::oper_grant(self, account, privs, expires)
    }
    fn oper_revoke(&mut self, account: &str) -> bool {
        Db::oper_revoke(self, account)
    }
    fn opers_list(&self) -> Vec<(String, Vec<String>, Option<u64>)> {
        Db::opers_list(self)
    }
    fn session_except_add(&mut self, mask: &str, limit: u32, reason: &str) {
        Db::session_except_add(self, mask, limit, reason)
    }
    fn session_except_del(&mut self, mask: &str) -> bool {
        Db::session_except_del(self, mask)
    }
    fn session_exceptions(&self) -> Vec<(String, u32, String)> {
        Db::session_exceptions(self)
    }
    fn register_channel(&mut self, name: &str, founder: &str) -> Result<(), ChanError> {
        Db::register_channel(self, name, founder)
    }
    fn drop_channel(&mut self, name: &str) -> Result<(), ChanError> {
        Db::drop_channel(self, name)
    }
    fn set_mlock(&mut self, name: &str, on: &str, off: &str, params: Vec<(char, String)>) -> Result<(), ChanError> {
        Db::set_mlock_params(self, name, on, off, params)
    }
    fn set_desc(&mut self, channel: &str, desc: &str) -> Result<(), ChanError> {
        Db::set_desc(self, channel, desc)
    }
    fn set_url(&mut self, channel: &str, url: &str) -> Result<(), ChanError> {
        Db::set_url(self, channel, url)
    }
    fn set_channel_email(&mut self, channel: &str, email: &str) -> Result<(), ChanError> {
        Db::set_channel_email(self, channel, email)
    }
    fn set_channel_setting(&mut self, channel: &str, setting: ChanSetting, on: bool) -> Result<(), ChanError> {
        Db::set_channel_setting(self, channel, setting, on)
    }
    fn set_kicker(&mut self, channel: &str, kicker: Kicker, on: bool) -> Result<(), ChanError> {
        Db::set_kicker(self, channel, kicker, on)
    }
    fn set_caps_kicker(&mut self, channel: &str, caps_min: u16, caps_percent: u16) -> Result<(), ChanError> {
        Db::set_caps_kicker(self, channel, caps_min, caps_percent)
    }
    fn set_flood_kicker(&mut self, channel: &str, lines: u16, secs: u16) -> Result<(), ChanError> {
        Db::set_flood_kicker(self, channel, lines, secs)
    }
    fn set_repeat_kicker(&mut self, channel: &str, times: u16) -> Result<(), ChanError> {
        Db::set_repeat_kicker(self, channel, times)
    }
    fn set_ttb(&mut self, channel: &str, ttb: u16) -> Result<(), ChanError> {
        Db::set_ttb(self, channel, ttb)
    }
    fn set_ban_expire(&mut self, channel: &str, secs: u32) -> Result<(), ChanError> {
        Db::set_ban_expire(self, channel, secs)
    }
    fn set_votekick(&mut self, channel: &str, votes: u16) -> Result<(), ChanError> {
        Db::set_votekick(self, channel, votes)
    }
    fn badword_add(&mut self, channel: &str, pattern: &str) -> Result<bool, ChanError> {
        Db::badword_add(self, channel, pattern)
    }
    fn badword_del(&mut self, channel: &str, pattern: &str) -> Result<bool, ChanError> {
        Db::badword_del(self, channel, pattern)
    }
    fn badword_clear(&mut self, channel: &str) -> Result<usize, ChanError> {
        Db::badword_clear(self, channel)
    }
    fn badwords(&self, channel: &str) -> Vec<String> {
        Db::badwords(self, channel).to_vec()
    }
    fn kicker_test(&self, channel: &str, text: &str) -> Option<String> {
        Db::kicker_test(self, channel, text)
    }
    fn copy_bot_config(&mut self, src: &str, dst: &str) -> Result<(), ChanError> {
        Db::copy_bot_config(self, src, dst)
    }
    fn trigger_add(&mut self, channel: &str, pattern: &str, response: &str, cooldown: u32) -> Result<bool, ChanError> {
        Db::trigger_add(self, channel, pattern, response, cooldown)
    }
    fn trigger_del(&mut self, channel: &str, index: usize) -> Result<bool, ChanError> {
        Db::trigger_del(self, channel, index)
    }
    fn trigger_clear(&mut self, channel: &str) -> Result<usize, ChanError> {
        Db::trigger_clear(self, channel)
    }
    fn triggers(&self, channel: &str) -> Vec<TriggerView> {
        Db::triggers(self, channel).iter().map(|t| TriggerView { pattern: t.pattern.clone(), response: t.response.clone(), cooldown: t.cooldown }).collect()
    }
    fn set_channel_topic(&mut self, channel: &str, topic: &str) -> Result<(), ChanError> {
        Db::set_channel_topic(self, channel, topic)
    }
    fn suspend_channel(&mut self, channel: &str, by: &str, reason: &str, expires: Option<u64>) -> Result<(), ChanError> {
        Db::suspend_channel(self, channel, by, reason, expires)
    }
    fn unsuspend_channel(&mut self, channel: &str) -> Result<bool, ChanError> {
        Db::unsuspend_channel(self, channel)
    }
    fn is_channel_suspended(&self, channel: &str) -> bool {
        Db::is_channel_suspended(self, channel)
    }
    fn channel_suspension(&self, channel: &str) -> Option<SuspensionView> {
        Db::channel_suspension(self, channel)
    }
    fn bot_add(&mut self, nick: &str, user: &str, host: &str, gecos: &str) -> Result<(), ChanError> {
        Db::bot_add(self, nick, user, host, gecos)
    }
    fn bot_change(&mut self, old: &str, new_nick: &str, user: &str, host: &str, gecos: &str) -> Result<(), ChanError> {
        Db::bot_change(self, old, new_nick, user, host, gecos)
    }
    fn bot_set_private(&mut self, nick: &str, private: bool) -> Result<bool, ChanError> {
        Db::bot_set_private(self, nick, private)
    }
    fn bot_del(&mut self, nick: &str) -> Result<bool, ChanError> {
        Db::bot_del(self, nick)
    }
    fn bot_del_all(&mut self) -> Result<usize, ChanError> {
        Db::bot_del_all(self)
    }
    fn bots(&self) -> Vec<BotView> {
        Db::bots(self).map(|b| BotView { nick: b.nick.clone(), user: b.user.clone(), host: b.host.clone(), gecos: b.gecos.clone(), private: b.private }).collect()
    }
    fn assign_bot(&mut self, channel: &str, bot: &str) -> Result<(), ChanError> {
        Db::assign_bot(self, channel, bot)
    }
    fn unassign_bot(&mut self, channel: &str) -> Result<bool, ChanError> {
        Db::unassign_bot(self, channel)
    }
    fn default_bot(&self) -> Option<String> {
        Db::default_bot(self).map(str::to_string)
    }
    fn set_default_bot(&mut self, bot: Option<&str>) -> Result<(), ChanError> {
        Db::set_default_bot(self, bot)
    }
    fn memo_send(&mut self, account: &str, from: &str, text: &str, receipt: bool) -> Result<(), RegError> {
        Db::memo_send(self, account, from, text, receipt)
    }
    fn memo_list(&self, account: &str) -> Vec<MemoView> {
        Db::memo_list(self, account)
    }
    fn memo_read(&mut self, account: &str, index: usize) -> Option<MemoView> {
        Db::memo_read(self, account, index)
    }
    fn memo_del(&mut self, account: &str, index: usize) -> bool {
        Db::memo_del(self, account, index)
    }
    fn memo_cancel(&mut self, account: &str, sender: &str) -> bool {
        Db::memo_cancel(self, account, sender)
    }
    fn memo_ignore_add(&mut self, account: &str, target: &str) -> bool {
        Db::memo_ignore_add(self, account, target)
    }
    fn memo_ignore_del(&mut self, account: &str, target: &str) -> bool {
        Db::memo_ignore_del(self, account, target)
    }
    fn memo_ignores(&self, account: &str) -> Vec<String> {
        Db::memo_ignores(self, account)
    }
    fn memo_is_ignored(&self, account: &str, sender: &str) -> bool {
        Db::memo_is_ignored(self, account, sender)
    }
    fn set_memo_notify(&mut self, account: &str, on: bool) -> bool {
        Db::set_memo_notify(self, account, on)
    }
    fn set_memo_limit(&mut self, account: &str, limit: Option<u32>) -> bool {
        Db::set_memo_limit(self, account, limit)
    }
    fn memo_notify_on(&self, account: &str) -> bool {
        Db::memo_notify_on(self, account)
    }
    fn memo_limit_of(&self, account: &str) -> Option<u32> {
        Db::memo_limit_of(self, account)
    }
    fn memo_check(&self, account: &str, sender: &str) -> Option<(bool, u64)> {
        Db::memo_check(self, account, sender)
    }
    fn unread_memos(&self, account: &str) -> usize {
        Db::unread_memos(self, account)
    }
    fn set_entrymsg(&mut self, channel: &str, msg: &str) -> Result<(), ChanError> {
        Db::set_entrymsg(self, channel, msg)
    }
    fn set_successor(&mut self, channel: &str, successor: Option<&str>) -> Result<(), ChanError> {
        Db::set_successor(self, channel, successor)
    }
    fn release_founded_channels(&mut self, account: &str) -> (Vec<(String, String)>, Vec<String>) {
        Db::release_founded_channels(self, account)
    }
    fn set_founder(&mut self, channel: &str, account: &str) -> Result<(), ChanError> {
        Db::set_founder(self, channel, account)
    }
    fn access_add(&mut self, channel: &str, account: &str, level: &str) -> Result<(), ChanError> {
        Db::access_add(self, channel, account, level)
    }
    fn access_del(&mut self, channel: &str, account: &str) -> Result<bool, ChanError> {
        Db::access_del(self, channel, account)
    }
    fn akick_add(&mut self, channel: &str, mask: &str, reason: &str) -> Result<(), ChanError> {
        Db::akick_add(self, channel, mask, reason)
    }
    fn akick_del(&mut self, channel: &str, mask: &str) -> Result<bool, ChanError> {
        Db::akick_del(self, channel, mask)
    }
    fn level_set(&mut self, channel: &str, cap: &str, role: &str) -> Result<(), ChanError> {
        Db::level_set(self, channel, cap, role)
    }
    fn level_reset(&mut self, channel: &str, cap: &str) -> Result<bool, ChanError> {
        Db::level_reset(self, channel, cap)
    }
}

fn channel_view(c: &ChannelInfo) -> ChannelView {
    ChannelView {
        name: c.name.clone(),
        founder: c.founder.clone(),
        ts: c.ts,
        lock_on: c.lock_on.clone(),
        lock_off: c.lock_off.clone(),
        lock_params: c.lock_params.clone(),
        access: c.access.iter().map(|a| ChanAccessView { account: a.account.clone(), level: a.level.clone() }).collect(),
        akick: c.akick.iter().map(|k| ChanAkickView { mask: k.mask.clone(), reason: k.reason.clone() }).collect(),
        levels: c.levels.iter().filter_map(|(cap, role)| Some((echo_api::LevelCap::parse(cap)?, echo_api::AccessRole::parse(role)?))).collect(),
        desc: c.desc.clone(),
        entrymsg: c.entrymsg.clone(),
        url: c.url.clone(),
        email: c.email.clone(),
        signkick: c.settings.signkick,
        private: c.settings.private,
        peace: c.settings.peace,
        secureops: c.settings.secureops,
        keeptopic: c.settings.keeptopic,
        topiclock: c.settings.topiclock,
        topic: c.topic.clone(),
        suspended: c.suspension.as_ref().is_some_and(|s| s.expires.is_none_or(|e| e > now())),
        assigned_bot: c.assigned_bot.clone(),
        bot_greet: c.settings.bot_greet,
        nobot: c.settings.nobot,
        kickers_active: c.kickers.any(),
    }
}
