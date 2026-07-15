    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("echo-log-{name}.jsonl"));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn cert(account: &str, fp: &str) -> Event {
        Event::CertAdded { account: account.into(), fp: fp.into() }
    }

    #[test]
    fn formats_unix_time_as_utc() {
        assert_eq!(echo_api::human_time(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(echo_api::human_time(1783844590), "2026-07-12 08:23:10 UTC");
    }

    #[test]
    fn glob_matches_hostmasks() {
        assert!(glob_match("*!*@host.example", "bob!~b@host.example"));
        assert!(glob_match("bob!*@*", "BOB!~b@1.2.3.4"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("nick?!*@*", "nickX!~x@h"));
        assert!(!glob_match("*!*@host.example", "bob!~b@other"));
        assert!(!glob_match("alice!*@*", "bob!~b@h"));
    }

    #[test]
    fn account_conflict_resolves_deterministically() {
        // `tag` (carried in the email field, a free identity slot here) labels
        // which of the two competing registrations we're looking at.
        let alice = |tag: &str, ts: u64, home: &str| Account {
            name: "alice".into(), email: Some(tag.into()),
            ts, home: home.into(), scram256: None, scram512: None, certfps: vec![], verified: true, ajoin: vec![], suspension: None, memos: vec![], greet: String::new(), vhost: None, vhost_request: None, last_seen: ts, noexpire: false, expiry_warned: false, oper_note: None,
        };
        let converge = |first: &Account, second: &Account| {
            let (mut acc, mut ch, mut gr, mut bo, mut hc, mut nd) = (HashMap::new(), HashMap::new(), HashMap::new(), HashMap::new(), HostConfig::default(), NetData::default());
            apply(&mut acc, &mut ch, &mut gr, &mut bo, &mut hc, &mut nd, Event::AccountRegistered(Box::new(first.clone())));
            apply(&mut acc, &mut ch, &mut gr, &mut bo, &mut hc, &mut nd, Event::AccountRegistered(Box::new(second.clone())));
            acc["alice"].email.clone().unwrap()
        };
        // Earlier registration wins, regardless of which claim applies first.
        let early = alice("EARLY", 100, "nodeB");
        let late = alice("LATE", 200, "nodeA");
        assert_eq!(converge(&early, &late), "EARLY");
        assert_eq!(converge(&late, &early), "EARLY", "commutative: same winner in either order");
        // Same ts: the lower origin wins, in either order.
        let a = alice("A", 100, "nodeA");
        let b = alice("B", 100, "nodeB");
        assert_eq!(converge(&a, &b), "A");
        assert_eq!(converge(&b, &a), "A", "ts tie broken by lower origin, either order");
        // Idempotent: re-delivering the winner keeps it.
        assert_eq!(converge(&a, &a), "A");
    }

    #[test]
    fn channel_state_is_node_local_but_persists() {
        let path = tmp("scope");
        {
            let mut db = Db::open(&path, "N1");
            db.register("alice", "pw", None).unwrap(); // global
            db.register_channel("#c", "alice").unwrap(); // local
            db.set_mlock("#c", "nt", "").unwrap(); // local
            // Only the account advances the version vector.
            assert_eq!(db.version_vector().get("N1"), Some(&0), "channels don't advance the vector");
            // A fresh peer is offered the account, never the channel.
            let missing = db.missing_for(&HashMap::new());
            assert_eq!(missing.len(), 1, "only the global account entry is offered: {missing:?}");
            assert!(matches!(missing[0].event, Event::AccountRegistered(_)));
        }
        // Reopen: node-local channel state replays from disk unchanged.
        let db = Db::open(&path, "N1");
        assert!(db.exists("alice"));
        assert_eq!(db.channel("#c").map(|c| c.lock_on.clone()), Some("nt".to_string()), "channel state persists locally");
        assert_eq!(db.version_vector().get("N1"), Some(&0), "vector unchanged after replay");
    }

    #[test]
    fn akick_add_del_and_match() {
        let mut db = Db::open(&tmp("akick"), "N1");
        db.register_channel("#c", "founder").unwrap();
        db.akick_add("#c", "*!*@bad.host", "spam").unwrap();
        let info = db.channel("#c").unwrap();
        assert!(info.akick_match("evil!~e@bad.host").is_some());
        assert!(info.akick_match("good!~g@ok.host").is_none());
        assert!(db.akick_del("#c", "*!*@bad.host").unwrap());
        assert!(!db.akick_del("#c", "*!*@bad.host").unwrap());
        assert!(db.channel("#c").unwrap().akick.is_empty());
    }

    // The auto-join list adds, updates a key in place, removes case-insensitively,
    // and replays from the event log after a reopen.
    #[test]
    fn ajoin_add_del_and_persist() {
        let p = tmp("ajoin");
        {
            let mut db = Db::open(&p, "N1");
            db.scram_iterations = 4096;
            db.register("alice", "pw", None).unwrap();
            assert!(db.ajoin_add("alice", "#chat", "").unwrap(), "newly added");
            assert!(!db.ajoin_add("alice", "#chat", "sekret").unwrap(), "re-add updates the key, not newly added");
            db.ajoin_add("alice", "#dev", "").unwrap();
            assert_eq!(db.ajoin_list("alice").len(), 2);
            assert_eq!(db.ajoin_list("alice")[0].key, "sekret", "key updated in place");
            assert!(db.ajoin_del("alice", "#CHAT").unwrap(), "case-insensitive remove");
            assert!(!db.ajoin_del("alice", "#chat").unwrap(), "already gone");
        }
        let db = Db::open(&p, "N1");
        assert_eq!(db.ajoin_list("alice").len(), 1, "list replays from the log");
        assert_eq!(db.ajoin_list("alice")[0].channel, "#dev");
    }

    // Channel SET options default off, toggle, and replay from the log.
    #[test]
    fn channel_settings_toggle_and_persist() {
        let p = tmp("chansettings");
        {
            let mut db = Db::open(&p, "N1");
            db.register_channel("#c", "boss").unwrap();
            assert!(!db.channel("#c").unwrap().settings.signkick, "defaults off");
            db.set_channel_setting("#c", ChanSetting::SignKick, true).unwrap();
            db.set_channel_setting("#c", ChanSetting::Private, true).unwrap();
            db.set_channel_setting("#c", ChanSetting::Private, false).unwrap();
            let s = db.channel("#c").unwrap().settings;
            assert!(s.signkick && !s.private, "one flag on, the other flipped back off");
        }
        let s = Db::open(&p, "N1").channel("#c").unwrap().settings;
        assert!(s.signkick && !s.private, "settings replay from the log");
    }

    // Access ranks order founder > op > voice > none for PEACE comparisons.
    #[test]
    fn access_rank_orders_founder_op_voice() {
        let mut db = Db::open(&tmp("rank"), "N1");
        db.register_channel("#c", "boss").unwrap();
        db.access_add("#c", "op1", "op").unwrap();
        db.access_add("#c", "v1", "voice").unwrap();
        let cv = Store::channel(&db, "#c").unwrap();
        assert_eq!(cv.access_rank(Some("boss")), 3);
        assert_eq!(cv.access_rank(Some("OP1")), 2, "case-insensitive");
        assert_eq!(cv.access_rank(Some("v1")), 1);
        assert_eq!(cv.access_rank(Some("nobody")), 0);
        assert_eq!(cv.access_rank(None), 0);
    }

    // Suspension sets/lifts, expires lazily, and replays from the log.
    #[test]
    fn suspend_lifts_expires_and_persists() {
        let p = tmp("suspend");
        {
            let mut db = Db::open(&p, "N1");
            db.scram_iterations = 4096;
            db.register("alice", "password1", None).unwrap();
            assert!(!db.is_suspended("alice"));
            db.suspend_account("alice", "oper", "spamming", None).unwrap();
            assert!(db.is_suspended("alice"));
            assert_eq!(db.suspension("alice").unwrap().reason, "spamming");
            assert!(db.unsuspend_account("alice").unwrap());
            assert!(!db.is_suspended("alice"));
            assert!(!db.unsuspend_account("alice").unwrap(), "already lifted");
            // A past expiry is not active, but the record still shows in INFO.
            db.suspend_account("alice", "oper", "temp", Some(1)).unwrap();
            assert!(!db.is_suspended("alice"), "expired suspension is inactive");
            assert!(db.suspension("alice").is_some());
        }
        {
            let mut db = Db::open(&p, "N1");
            db.suspend_account("alice", "oper", "again", None).unwrap();
        }
        assert!(Db::open(&p, "N1").is_suspended("alice"), "suspension replays from the log");
    }

    // A channel suspension lifts, expires lazily, and survives compaction + reopen.
    #[test]
    fn channel_suspend_lifts_persists_and_compacts() {
        let p = tmp("chansuspend");
        let mut db = Db::open(&p, "N1");
        db.register_channel("#c", "boss").unwrap();
        db.suspend_channel("#c", "oper", "raided", Some(1)).unwrap();
        assert!(!db.is_channel_suspended("#c"), "a past expiry is inactive");
        db.suspend_channel("#c", "oper", "raided", None).unwrap();
        assert!(db.is_channel_suspended("#c"));
        db.compact().unwrap(); // the snapshot must retain the suspension
        drop(db);
        let db = Db::open(&p, "N1");
        assert!(db.is_channel_suspended("#c"), "survives compaction + reopen");
        assert_eq!(db.channel_suspension("#c").unwrap().by, "oper");
    }

    // The bot registry adds (case-insensitively unique), deletes, and replays.
    #[test]
    fn bots_add_del_and_persist() {
        let p = tmp("bots");
        {
            let mut db = Db::open(&p, "N1");
            assert_eq!(db.bots().count(), 0);
            db.bot_add("Bendy", "bot", "services.host", "A helper").unwrap();
            assert!(matches!(db.bot_add("bendy", "x", "y", "z"), Err(ChanError::Exists)), "dup is case-insensitive");
            assert_eq!(db.bots().count(), 1);
            assert!(db.bot_del("BENDY").unwrap(), "case-insensitive delete");
            assert!(!db.bot_del("bendy").unwrap(), "already gone");
        }
        {
            let mut db = Db::open(&p, "N1");
            db.bot_add("Botty", "b", "h", "g").unwrap();
        }
        let db = Db::open(&p, "N1");
        assert_eq!(db.bots().count(), 1, "bots replay from the log");
        assert_eq!(db.bots().next().unwrap().nick, "Botty");
    }

    // Memos send, mark read on read, delete (shifting indices), and replay.
    #[test]
    fn memos_send_read_delete_and_persist() {
        let p = tmp("memos");
        {
            let mut db = Db::open(&p, "N1");
            db.scram_iterations = 4096;
            db.register("alice", "password1", None).unwrap();
            assert_eq!(db.unread_memos("alice"), 0);
            db.memo_send("alice", "bob", "hello there").unwrap();
            db.memo_send("alice", "carol", "second").unwrap();
            assert_eq!(db.unread_memos("alice"), 2);
            let m = db.memo_read("alice", 0).unwrap();
            assert_eq!(m.from, "bob");
            assert_eq!(db.unread_memos("alice"), 1, "reading marks it read");
            assert!(db.memo_del("alice", 0));
            assert_eq!(db.memo_list("alice").len(), 1);
            assert_eq!(db.memo_list("alice")[0].text, "second", "delete shifts indices");
        }
        let db = Db::open(&p, "N1");
        assert_eq!(db.memo_list("alice").len(), 1, "memos replay from the log");
        assert_eq!(db.unread_memos("alice"), 1);
    }

    // A wrong code is tolerated a few times, then the code is burned so it can't
    // be ground down online even though it is short.
    #[test]
    fn code_burns_after_too_many_wrong_guesses() {
        let mut db = Db::open(&tmp("code"), "N1");
        db.scram_iterations = 4096;
        db.register("alice", "password", None).unwrap();
        let code = db.issue_code("alice", CodeKind::Reset);
        for _ in 0..CODE_TRIES {
            assert!(!db.take_code("alice", CodeKind::Reset, "WRONG000"), "wrong guess fails");
        }
        assert!(!db.take_code("alice", CodeKind::Reset, &code), "the real code is now burned too");
    }

    // Password auth backs off after a few failures and the throttle clears on success.
    #[test]
    fn auth_throttle_locks_then_clears() {
        let mut db = Db::open(&tmp("throttle"), "N1");
        for _ in 0..=AUTH_FREE_TRIES {
            db.note_auth("mallory", false);
        }
        assert!(db.auth_lockout("mallory").is_some(), "locked out after the free tries");
        db.note_auth("mallory", true);
        assert!(db.auth_lockout("mallory").is_none(), "a success clears the throttle");
    }

    // Locally-authored events get an incrementing per-origin seq and a ticking
    // Lamport clock.
    #[test]
    fn append_stamps_monotonic_metadata() {
        let (mut log, ev) = EventLog::open(tmp("append"), "nodeA".into());
        assert!(ev.is_empty());
        log.append(cert("x", "f1")).unwrap();
        log.append(cert("x", "f2")).unwrap();
        assert_eq!(log.versions.get("nodeA"), Some(&1)); // seqs 0 then 1
        assert_eq!(log.lamport, 2);
        assert_eq!(log.next_seq(), 2);
    }

    // Reopening the log recovers the clocks so seqs are never reused.
    #[test]
    fn reopen_recovers_clocks() {
        let p = tmp("reopen");
        {
            let (mut log, _) = EventLog::open(p.clone(), "nodeA".into());
            log.append(cert("x", "f1")).unwrap();
            log.append(cert("x", "f2")).unwrap();
        }
        let (log, events) = EventLog::open(p, "nodeA".into());
        assert_eq!(events.len(), 2);
        assert_eq!(log.next_seq(), 2);
        assert_eq!(log.lamport, 2);
    }

    // Ingesting a peer's entry applies it once and advances the Lamport clock;
    // a re-delivered entry is dropped (gossip convergence).
    #[test]
    fn ingest_is_idempotent() {
        let (mut log, _) = EventLog::open(tmp("ingest"), "local".into());
        let entry = LogEntry { origin: "peer".into(), seq: 0, lamport: 5, event: cert("x", "f") };
        assert!(log.ingest(entry.clone()).unwrap().is_some(), "first ingest applies");
        assert_eq!(log.versions.get("peer"), Some(&0));
        assert_eq!(log.lamport, 6, "receive rule: max(local, remote) + 1");
        assert!(log.ingest(entry).unwrap().is_none(), "duplicate ingest is a no-op");
    }

    // The gossip seam folds a peer's account into local state.
    #[test]
    fn db_ingest_folds_peer_account() {
        let mut db = Db::open(tmp("dbingest"), "local");
        db.scram_iterations = 4096;
        db.register("alice", "pw", None).unwrap();
        let bob = Account {
            name: "bob".into(), email: None,
            ts: 0, home: "peer".into(), scram256: None, scram512: None, certfps: vec![], verified: true, ajoin: vec![], suspension: None, memos: vec![], greet: String::new(), vhost: None, vhost_request: None, last_seen: 0, noexpire: false, expiry_warned: false, oper_note: None,
        };
        let entry = LogEntry { origin: "peer".into(), seq: 0, lamport: 1, event: Event::AccountRegistered(Box::new(bob)) };
        db.ingest(entry).unwrap();
        assert!(db.exists("bob"), "peer's account is present locally");
        assert!(db.exists("alice"), "local account still there");
    }

    // Compaction collapses churn to one entry per account and survives a reload.
    #[test]
    fn compact_preserves_state_and_shrinks() {
        let p = tmp("compact");
        let mut db = Db::open(&p, "local");
        db.scram_iterations = 4096;
        db.register("alice", "pw", None).unwrap();
        db.register("bob", "pw", None).unwrap();
        for i in 0..10u32 {
            let fp = format!("{i:032x}");
            db.certfp_add("alice", &fp).unwrap();
            db.certfp_del("alice", &fp).unwrap();
        }
        let kept = "bb".repeat(16);
        db.certfp_add("bob", &kept).unwrap();

        let before = db.log.len();
        db.compact().unwrap();
        assert!(db.log.len() < before, "log shrank: {before} -> {}", db.log.len());
        assert_eq!(db.log.len(), 2, "one entry per account");

        drop(db);
        let db = Db::open(&p, "local");
        assert!(db.authenticate("alice", "pw").is_some(), "password survives compaction");
        assert!(db.certfps("alice").is_empty(), "churned certs are gone");
        assert_eq!(db.certfps("bob"), &[kept][..], "kept cert survives");
    }

    // An account provisioned from a SCRAM verifier alone (external authority)
    // must authenticate over the PLAIN / IDENTIFY path (db.authenticate), not
    // only over SCRAM — the verifier is the sole credential, so a backfilled
    // member can still `/msg NickServ IDENTIFY`.
    #[test]
    fn provisioned_account_authenticates_over_plain() {
        let mut db = Db::open(tmp("prov-plain"), "N1");
        db.scram_iterations = 4096;
        let creds = Db::derive_credentials("hunter2", 4096).unwrap();
        db.provision_account("ext", &creds.scram256, "", None).unwrap();

        // The verifier is the only credential on file, and PLAIN/IDENTIFY works.
        assert!(db.test_verifier("ext").is_some(), "provisioned: verifier is the credential");
        assert_eq!(db.authenticate("ext", "hunter2"), Some("ext"), "right password logs in");
        assert!(db.authenticate("ext", "wrong").is_none(), "wrong password rejected");
    }

    // A peer with an empty log converges from a node that has already compacted.
    #[test]
    fn compacted_node_still_converges() {
        let mut a = Db::open(tmp("compA"), "A");
        a.scram_iterations = 4096;
        a.register("alice", "pw", None).unwrap();
        let fp = "cc".repeat(16);
        a.certfp_add("alice", &fp).unwrap();
        a.compact().unwrap();

        let mut b = Db::open(tmp("compB"), "B");
        b.scram_iterations = 4096;
        for entry in a.missing_for(&b.version_vector()) {
            b.ingest(entry).unwrap();
        }
        assert!(b.exists("alice"), "B converges from a compacted node");
        assert_eq!(b.certfps("alice"), &[fp][..], "certs arrive folded into the snapshot");
    }

    // Channels register (case-insensitively unique), persist, and drop.
    #[test]
    fn channels_register_drop_and_persist() {
        let p = tmp("chan");
        let mut db = Db::open(&p, "local");
        db.register_channel("#Chat", "alice").unwrap();
        assert!(matches!(db.register_channel("#chat", "bob"), Err(ChanError::Exists)), "dup is case-insensitive");
        assert_eq!(db.channel("#CHAT").map(|c| c.founder.as_str()), Some("alice"));

        drop(db);
        let mut db = Db::open(&p, "local");
        assert_eq!(db.channel("#chat").map(|c| c.founder.as_str()), Some("alice"), "survives reopen");
        db.drop_channel("#chat").unwrap();
        assert!(db.channel("#chat").is_none());
        assert!(matches!(db.drop_channel("#chat"), Err(ChanError::NoChannel)));
    }

    // Mode lock persists, renders the applied string, and detects violations.
    #[test]
    fn mode_lock_persists_and_enforces() {
        let p = tmp("mlock");
        let mut db = Db::open(&p, "local");
        db.register_channel("#chan", "alice").unwrap();
        db.set_mlock("#chan", "nt", "s").unwrap();

        let info = db.channel("#chan").unwrap();
        assert_eq!(info.lock_modes(), "+rnt-s");
        assert_eq!(info.enforce("-nt"), Some("+nt".to_string())); // locked-on removed
        assert_eq!(info.enforce("+s"), Some("-s".to_string()));   // locked-off added
        assert_eq!(info.enforce("-r"), Some("+r".to_string()));   // +r always locked
        assert_eq!(info.enforce("+m"), None);                     // unrelated mode ignored

        drop(db);
        let db = Db::open(&p, "local");
        assert_eq!(db.channel("#chan").unwrap().lock_modes(), "+rnt-s", "survives reopen");
    }

    // Access list drives join modes, is case-insensitive, and persists.
    #[test]
    fn access_list_grants_join_modes() {
        let p = tmp("access");
        let mut db = Db::open(&p, "local");
        db.register_channel("#c", "boss").unwrap();
        db.access_add("#c", "alice", "op").unwrap();
        db.access_add("#c", "bob", "voice").unwrap();

        let info = db.channel("#c").unwrap();
        assert_eq!(info.join_mode("boss"), Some("+o"));  // founder
        assert_eq!(info.join_mode("ALICE"), Some("+o")); // op, case-insensitive
        assert_eq!(info.join_mode("bob"), Some("+v"));   // voice
        assert_eq!(info.join_mode("nobody"), None);

        assert!(db.access_del("#c", "alice").unwrap());
        assert!(!db.access_del("#c", "alice").unwrap());

        drop(db);
        let db = Db::open(&p, "local");
        assert_eq!(db.channel("#c").unwrap().join_mode("bob"), Some("+v"), "survives reopen");
        assert_eq!(db.channel("#c").unwrap().join_mode("alice"), None, "removal survives reopen");
    }
