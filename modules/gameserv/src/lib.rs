//! GamesServ — a server-authoritative referee for tic-tac-toe, Connect Four and
//! chess, with a per-game ranked ladder. Every move is validated here and the
//! winner decided by the server, so a client can never cheat (games stay
//! server-side). Players drive games over `/msg GamesServ`; the machine-readable
//! board is pushed to each player on an invisible client-only TAGMSG
//! (`+tchatou.fr/gs`) that only the web client renders — IRC clients see just the
//! human notices. The ranked ladder rides StatServ's persisted counters.
//!
//! `board.rs` is the referee (typed rules + state); `chess.rs` is the chess engine.

use std::collections::HashMap;

use echo_api::{HelpEntry, NetAction, NetView, Sender, Service, ServiceCtx, Store};

#[path = "chess.rs"]
mod chess;
#[path = "board.rs"]
mod board;

use board::{GameType, Game, Outcome, Side, Status};

// Cap concurrent games per identity so a flood of never-finished challenges
// can't grow the map without bound (finished games are dropped immediately).
const MAX_GAMES_PER_USER: usize = 5;
const TYPES: [GameType; 3] = [GameType::Chess, GameType::C4, GameType::Ttt];

const BLURB: &str = "GamesServ referees \x02tic-tac-toe\x02, \x02Connect Four\x02 and \x02chess\x02 — it checks every move and keeps a ranked ladder. Challenge someone, then take turns. Moves: ttt cell \x020-8\x02, c4 column \x020-6\x02, chess \x02UCI\x02 (e2e4).";

const TOPICS: &[HelpEntry] = &[
    HelpEntry { cmd: "CHALLENGE", summary: "challenge someone to a game", detail: "Syntax: \x02CHALLENGE <nick> <ttt|c4|chess>\x02\nChallenges a user. They accept with \x02ACCEPT\x02; you move first." },
    HelpEntry { cmd: "ACCEPT", summary: "accept a challenge", detail: "Syntax: \x02ACCEPT [id]\x02\nAccepts a pending challenge (the most recent one if no id is given)." },
    HelpEntry { cmd: "DECLINE", summary: "decline a challenge", detail: "Syntax: \x02DECLINE [id]\x02\nDeclines a pending challenge." },
    HelpEntry { cmd: "MOVE", summary: "make a move", detail: "Syntax: \x02MOVE <id> <move>\x02\nMakes a move: ttt cell \x020-8\x02, c4 column \x020-6\x02, chess \x02UCI\x02 like e2e4 (e7e8q to promote)." },
    HelpEntry { cmd: "RESIGN", summary: "resign a game", detail: "Syntax: \x02RESIGN <id>\x02\nResigns an active game; your opponent wins." },
    HelpEntry { cmd: "GAMES", summary: "list your games", detail: "Syntax: \x02GAMES\x02\nLists your pending and active games with their ids." },
    HelpEntry { cmd: "STATS", summary: "show ranked stats", detail: "Syntax: \x02STATS [nick]\x02\nShows a player's ranked record per game type (yours if no nick)." },
    HelpEntry { cmd: "TOP", summary: "show the leaderboard", detail: "Syntax: \x02TOP [ttt|c4|chess]\x02\nShows the top ranked players for a game type (chess by default)." },
];

// One (account, game type) ladder row, materialised from the shared stat counters
// that StatServ persists. Points are DERIVED (win +10, loss -8, floored at 0), so
// the ladder needs only monotonic w/l/d counters — nothing to keep in sync.
#[derive(Default, Clone)]
struct Stats {
    wins: u32,
    losses: u32,
    draws: u32,
}

impl Stats {
    fn points(&self) -> i32 {
        (10 * self.wins as i32 - 8 * self.losses as i32).max(0)
    }

    fn rank(&self) -> &'static str {
        let p = self.points();
        if p >= 800 {
            "Master"
        } else if p >= 400 {
            "Gold"
        } else if p >= 150 {
            "Silver"
        } else {
            "Bronze"
        }
    }

    fn any(&self) -> bool {
        self.wins > 0 || self.losses > 0 || self.draws > 0
    }
}

// The ladder lives in the shared counters, keyed `game.<type>.<w|l|d>.<account>`.
fn counter_key(gt: GameType, kind: char, account: &str) -> String {
    format!("game.{}.{kind}.{account}", gt.wire())
}

fn read_stats(counters: &[(String, u64)], gt: GameType, account: &str) -> Stats {
    let get = |kind: char| {
        let key = counter_key(gt, kind, account);
        counters.iter().find(|(k, _)| *k == key).map(|(_, v)| *v as u32).unwrap_or(0)
    };
    Stats { wins: get('w'), losses: get('l'), draws: get('d') }
}

// A player's post-game record: the counter bumps land after the command, so fold
// this game's delta into the snapshot for the immediate rank push.
fn read_stats_with_delta(counters: &[(String, u64)], gt: GameType, account: &str, side: Side, outcome: Option<Outcome>) -> Stats {
    let mut s = read_stats(counters, gt, account);
    match outcome {
        Some(Outcome::Draw) => s.draws += 1,
        Some(Outcome::Win(w)) if w == side => s.wins += 1,
        Some(Outcome::Win(_)) => s.losses += 1,
        None => {}
    }
    s
}

pub struct GameServ {
    pub uid: String,
    games: HashMap<u64, Game>,
    nextid: u64,
}

impl GameServ {
    pub fn new(uid: String) -> Self {
        Self { uid, games: HashMap::new(), nextid: 1 }
    }

    // A player's game identity: their account if registered, else their connection
    // UID (not their nick, which is mutable — keying on it lets a nick-reuser hijack
    // an abandoned guest game, and lets a nick-cycler evade the per-user game cap).
    // `nick_a`/`nick_b` hold the display name separately.
    fn ident<'a>(from: &'a Sender) -> &'a str {
        from.account.unwrap_or(from.uid)
    }

    // The side an account plays in a game (A = challenger), or None if not a party.
    fn side_of(g: &Game, account: &str) -> Option<Side> {
        if g.acc_a == account {
            Some(Side::A)
        } else if g.acc_b == account {
            Some(Side::B)
        } else {
            None
        }
    }

    fn do_challenge(&mut self, me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView) {
        let (Some(&target), Some(&game)) = (args.get(1), args.get(2)) else {
            ctx.notice(me, from.uid, "Syntax: CHALLENGE <nick> <ttt|c4|chess>");
            return;
        };
        let Some(gt) = GameType::from_arg(game) else {
            ctx.notice(me, from.uid, "Unknown game. Available: \x02ttt\x02 (tic-tac-toe), \x02c4\x02 (Connect Four), \x02chess\x02.");
            return;
        };
        let Some(tuid) = net.uid_by_nick(target).map(str::to_string) else {
            ctx.notice(me, from.uid, format!("\x02{target}\x02 is not online."));
            return;
        };
        let meid = Self::ident(from).to_string();
        let target_acc = net.account_of(&tuid).map(str::to_string);
        // Key the target by the same identity ident() uses (account, else UID), or a
        // guest target's acc_b (their nick) never matches their later meid.
        let target_id = target_acc.clone().unwrap_or_else(|| tuid.clone());
        // Reject self-challenge on the GAME IDENTITY, not just the connection uid:
        // two sessions logged into one account would otherwise play a "ranked" game
        // against themselves and farm rating.
        if target_id == meid {
            ctx.notice(me, from.uid, "You cannot challenge yourself.");
            return;
        }
        // Global cap: the per-user cap keys on a churnable identity (a guest's nick),
        // so a single connection could otherwise cycle nicks to grow the games map
        // without bound. Bounding the total makes that impossible regardless.
        const MAX_GAMES_TOTAL: usize = 500;
        if self.games.len() >= MAX_GAMES_TOTAL {
            ctx.notice(me, from.uid, "The game server is at capacity right now. Please try again shortly.");
            return;
        }
        let mine = self.games.values().filter(|g| g.acc_a == meid || g.acc_b == meid).count();
        if mine >= MAX_GAMES_PER_USER {
            ctx.notice(me, from.uid, format!("You have too many games in progress (max {MAX_GAMES_PER_USER}). Finish or resign one first."));
            return;
        }
        let id = self.nextid;
        self.nextid += 1;
        let g = Game::new(
            id,
            gt,
            meid,
            from.account.is_some(),
            target_id,
            target_acc.is_some(),
            from.nick.to_string(),
            target.to_string(),
        );
        self.games.insert(id, g);
        ctx.notice(me, from.uid, format!("Challenge \x02#{id}\x02 ({}) sent to \x02{target}\x02.", gt.wire()));
        ctx.notice(me, &tuid, format!("{} challenges you to {} (game #{id}). \x02/msg GamesServ ACCEPT {id}\x02", from.nick, gt.wire()));
        let g = &self.games[&id];
        push_one(g, Side::A, "pending", me, net, ctx); // challenger: waiting
        push_one(g, Side::B, "offer", me, net, ctx); // target: can accept/decline
    }

    fn do_accept(&mut self, me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView) {
        let meid = Self::ident(from).to_string();
        let id = match args.get(1) {
            Some(&s) => s.parse::<u64>().ok().filter(|id| self.games.get(id).is_some_and(|g| g.status == Status::Pending && g.acc_b == meid)),
            None => self.games.iter().find(|(_, g)| g.status == Status::Pending && g.acc_b == meid).map(|(id, _)| *id),
        };
        let Some(id) = id else {
            ctx.notice(me, from.uid, "No pending challenge to accept.");
            return;
        };
        let g = self.games.get_mut(&id).unwrap();
        g.status = Status::Active;
        g.nick_b = from.nick.to_string();
        let glyph = g.glyph(Side::B);
        ctx.notice(me, from.uid, format!("Game \x02#{id}\x02 started. You are \x02{glyph}\x02."));
        push_state(&self.games[&id], me, net, ctx);
    }

    fn do_decline(&mut self, me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView) {
        let meid = Self::ident(from).to_string();
        let want: Option<u64> = args.get(1).and_then(|s| s.parse().ok());
        let id = self.games.iter().find(|(id, g)| {
            g.status == Status::Pending && g.acc_b == meid && want.is_none_or(|w| w == **id)
        }).map(|(id, _)| *id);
        let Some(id) = id else {
            ctx.notice(me, from.uid, "No pending challenge to decline.");
            return;
        };
        let g = self.games.remove(&id).unwrap();
        if let Some(auid) = net.uid_by_nick(&g.nick_a).map(str::to_string) {
            ctx.notice(me, &auid, format!("{} declined your challenge #{id}.", from.nick));
        }
        ctx.notice(me, from.uid, "Declined.");
    }

    fn do_move(&mut self, me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView) {
        let (Some(&ids), Some(&mv)) = (args.get(1), args.get(2)) else {
            ctx.notice(me, from.uid, "Syntax: MOVE <id> <move>");
            return;
        };
        let id: u64 = ids.parse().unwrap_or(0);
        let meid = Self::ident(from).to_string();
        // Apply under a scoped mutable borrow, then release it before pushing.
        let term = {
            let Some(g) = self.games.get_mut(&id) else {
                ctx.notice(me, from.uid, "No active game with that id.");
                return;
            };
            let side = Self::side_of(g, &meid);
            let (Some(side), true) = (side, g.status == Status::Active) else {
                ctx.notice(me, from.uid, "No active game with that id.");
                return;
            };
            match side {
                Side::A => g.nick_a = from.nick.to_string(),
                Side::B => g.nick_b = from.nick.to_string(),
            }
            if !board::apply_move(g, side, mv) {
                ctx.notice(me, from.uid, "Illegal move (or not your turn).");
                return;
            }
            board::terminal(g)
        };
        match term {
            Some(outcome) => self.finish(id, outcome, me, net, ctx),
            None => push_state(&self.games[&id], me, net, ctx),
        }
    }

    fn do_resign(&mut self, me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView) {
        let Some(&ids) = args.get(1) else {
            ctx.notice(me, from.uid, "Syntax: RESIGN <id>");
            return;
        };
        let id: u64 = ids.parse().unwrap_or(0);
        let meid = Self::ident(from).to_string();
        let winner = match self.games.get(&id) {
            Some(g) if g.status == Status::Active => match Self::side_of(g, &meid) {
                Some(side) => Outcome::Win(side.other()),
                None => {
                    ctx.notice(me, from.uid, "No active game with that id.");
                    return;
                }
            },
            _ => {
                ctx.notice(me, from.uid, "No active game with that id.");
                return;
            }
        };
        ctx.notice(me, from.uid, format!("You resigned game #{id}."));
        self.finish(id, winner, me, net, ctx);
    }

    // End a game: record the result, update the ladder (only when BOTH players are
    // registered), push the final state + refreshed stats, and drop the game.
    fn finish(&mut self, id: u64, outcome: Outcome, me: &str, net: &dyn NetView, ctx: &mut ServiceCtx) {
        let Some(mut g) = self.games.remove(&id) else { return };
        g.status = Status::Over;
        g.result = Some(outcome);
        let gt = g.gtype();
        let ranked = g.a_reg && g.b_reg;
        if ranked {
            match outcome {
                Outcome::Draw => {
                    ctx.count(counter_key(gt, 'd', &g.acc_a));
                    ctx.count(counter_key(gt, 'd', &g.acc_b));
                }
                Outcome::Win(w) => {
                    let (wacc, lacc) = match w {
                        Side::A => (&g.acc_a, &g.acc_b),
                        Side::B => (&g.acc_b, &g.acc_a),
                    };
                    ctx.count(counter_key(gt, 'w', wacc));
                    ctx.count(counter_key(gt, 'l', lacc));
                }
            }
        }
        // The counter bumps land AFTER this command, so fold this game's delta into
        // the pushed rank (only when ranked; casual games leave the ladder be).
        let counters = net.stat_counters();
        let delta = ranked.then_some(outcome);
        push_state(&g, me, net, ctx);
        if g.a_reg {
            let s = read_stats_with_delta(&counters, gt, &g.acc_a, Side::A, delta);
            push_stats(&counters, &g.acc_a, &g.nick_a, me, net, ctx, Some((gt, &s)));
        }
        if g.b_reg {
            let s = read_stats_with_delta(&counters, gt, &g.acc_b, Side::B, delta);
            push_stats(&counters, &g.acc_b, &g.nick_b, me, net, ctx, Some((gt, &s)));
        }
    }

    fn do_games(&self, me: &str, from: &Sender, ctx: &mut ServiceCtx) {
        let meid = Self::ident(from).to_string();
        let mut ids: Vec<u64> = self.games.iter().filter(|(_, g)| g.acc_a == meid || g.acc_b == meid).map(|(id, _)| *id).collect();
        ids.sort_unstable();
        if ids.is_empty() {
            ctx.notice(me, from.uid, "You have no games. Use \x02CHALLENGE <nick> <game>\x02.");
            return;
        }
        for id in ids {
            let g = &self.games[&id];
            let opp = if g.acc_a == meid { &g.nick_b } else { &g.nick_a };
            ctx.notice(me, from.uid, format!("#{}  {}  vs {}  [{}]", g.id, g.gtype().wire(), opp, g.status.wire()));
        }
    }

    fn do_stats(&self, me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView) {
        let who = if let Some(&t) = args.get(1) {
            net.uid_by_nick(t).and_then(|u| net.account_of(u)).map(str::to_string).unwrap_or_else(|| t.to_string())
        } else if let Some(a) = from.account {
            a.to_string()
        } else {
            ctx.notice(me, from.uid, "Log in or specify a nick.");
            return;
        };
        let counters = net.stat_counters();
        push_stats(&counters, &who, from.nick, me, net, ctx, None); // machine lines for the UI
        ctx.notice(me, from.uid, format!("\x02{who}\x02 — classement Jeux"));
        let mut any = false;
        for gt in TYPES {
            let s = read_stats(&counters, gt, &who);
            if s.any() {
                any = true;
                ctx.notice(me, from.uid, format!(
                    "  \x02{}\x02  \x02{}\x02 — {} pts ({}V {}D {}N)",
                    gt.label(), s.rank(), s.points(), s.wins, s.losses, s.draws
                ));
            }
        }
        if !any {
            ctx.notice(me, from.uid, "  (aucune partie classée pour l'instant)");
        }
    }

    fn do_top(&self, me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView) {
        let gt = match args.get(1) {
            Some(&t) => match GameType::from_arg(t) {
                Some(gt) => gt,
                None => {
                    ctx.notice(me, from.uid, "Unknown game. Use \x02TOP ttt|c4|chess\x02.");
                    return;
                }
            },
            None => GameType::Chess,
        };
        // Aggregate the per-account w/l/d counters for this game type.
        let counters = net.stat_counters();
        let prefix = format!("game.{}.", gt.wire());
        let mut map: HashMap<String, Stats> = HashMap::new();
        for (k, v) in &counters {
            let Some(rest) = k.strip_prefix(&prefix) else { continue };
            let Some((kind, acct)) = rest.split_once('.') else { continue };
            let e = map.entry(acct.to_string()).or_default();
            match kind {
                "w" => e.wins = *v as u32,
                "l" => e.losses = *v as u32,
                "d" => e.draws = *v as u32,
                _ => {}
            }
        }
        let mut all: Vec<(String, Stats)> = map.into_iter().filter(|(_, s)| s.points() > 0).collect();
        all.sort_by_key(|(_, s)| std::cmp::Reverse(s.points()));
        push_tag(me, net, from.nick, &format!("GS$TOPSTART {}", gt.wire()), ctx);
        if all.is_empty() {
            ctx.notice(me, from.uid, format!("Classement \x02{}\x02 vide. Sois le premier à gagner !", gt.label()));
            return;
        }
        ctx.notice(me, from.uid, format!("\x02Classement {} :\x02", gt.label()));
        for (rank, (acc, s)) in all.iter().take(10).enumerate() {
            let rank = rank + 1;
            ctx.notice(me, from.uid, format!("{rank:2}. {acc:<16} {}  {} pts", s.rank(), s.points()));
            push_tag(me, net, from.nick, &format!("GS$TOPROW {} {rank} {acc} {} {}", gt.wire(), s.rank(), s.points()), ctx);
        }
    }
}

// ── web-sync pushes (free functions so they never borrow the GameServ state) ──

// Client-only tag on a TAGMSG: invisible in chat, read only by the web client.
fn push_tag(me: &str, net: &dyn NetView, nick: &str, payload: &str, ctx: &mut ServiceCtx) {
    if let Some(uid) = net.uid_by_nick(nick) {
        ctx.actions.push(NetAction::Raw(format!("@+tchatou.fr/gs={} :{} TAGMSG {}", board::escape_tag(payload), me, uid)));
    }
}

// The GS# state line for one side. `status_override` lets a challenge show as
// "pending" to the challenger and "offer" to the target.
fn push_one(g: &Game, viewer: Side, status_override: &str, me: &str, net: &dyn NetView, ctx: &mut ServiceCtx) {
    let (nick, opp) = match viewer {
        Side::A => (&g.nick_a, &g.nick_b),
        Side::B => (&g.nick_b, &g.nick_a),
    };
    let status = if status_override.is_empty() { g.status.wire() } else { status_override };
    let res = match (g.status, g.result) {
        (Status::Over, Some(Outcome::Draw)) => "draw",
        (Status::Over, Some(Outcome::Win(w))) => if w == viewer { "win" } else { "loss" },
        _ => "none",
    };
    let payload = format!(
        "GS# {} g={} s={} t={} me={} opp={} st={} r={}",
        g.id, g.gtype().wire(), g.encode(), g.glyph(g.turn), g.glyph(viewer), opp, status, res
    );
    push_tag(me, net, nick, &payload, ctx);
}

fn push_state(g: &Game, me: &str, net: &dyn NetView, ctx: &mut ServiceCtx) {
    push_one(g, Side::A, "", me, net, ctx);
    push_one(g, Side::B, "", me, net, ctx);
}

// One GS$ stats line per game type (for the client's rank strip / profile badge),
// read from the counter snapshot. `override_ty` shows a just-finished game's
// post-game record even though the counter bump hasn't landed yet.
fn push_stats(counters: &[(String, u64)], account: &str, to_nick: &str, me: &str, net: &dyn NetView, ctx: &mut ServiceCtx, override_ty: Option<(GameType, &Stats)>) {
    for gt in TYPES {
        let s = match override_ty {
            Some((oty, os)) if oty == gt => os.clone(),
            _ => read_stats(counters, gt, account),
        };
        let payload = format!("GS$ {} {} r={} p={} w={} l={} d={}", account, gt.wire(), s.rank(), s.points(), s.wins, s.losses, s.draws);
        push_tag(me, net, to_nick, &payload, ctx);
    }
}

impl Service for GameServ {
    fn nick(&self) -> &str {
        // "GameServ" (singular) is reserved on this network; the games service is
        // "GamesServ" here.
        "GamesServ"
    }
    fn uid(&self) -> &str {
        &self.uid
    }
    fn gecos(&self) -> &str {
        "Game Service"
    }

    fn help_topics(&self) -> (&'static str, &'static [HelpEntry]) {
        (BLURB, TOPICS)
    }

    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView, _store: &mut dyn Store) {
        let me = self.uid.clone();
        match args.first().map(|s| s.to_ascii_uppercase()).as_deref() {
            Some("CHALLENGE") => self.do_challenge(&me, from, args, ctx, net),
            Some("ACCEPT") => self.do_accept(&me, from, args, ctx, net),
            Some("DECLINE") => self.do_decline(&me, from, args, ctx, net),
            Some("MOVE") => self.do_move(&me, from, args, ctx, net),
            Some("RESIGN") => self.do_resign(&me, from, args, ctx, net),
            Some("GAMES") => self.do_games(&me, from, ctx),
            Some("STATS") => self.do_stats(&me, from, args, ctx, net),
            Some("TOP") => self.do_top(&me, from, args, ctx, net),
            Some("HELP") | None => echo_api::help(&me, from, ctx, BLURB, TOPICS, args.get(1).copied()),
            Some(other) => ctx.notice(&me, from.uid, format!("I don't know \x02{other}\x02. Try \x02HELP\x02.")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The ladder is materialised from the shared counters; points derive from w/l.
    #[test]
    fn ladder_reads_counters_and_derives_points() {
        let counters = vec![
            ("game.chess.w.Reverse".to_string(), 5u64),
            ("game.chess.l.Reverse".to_string(), 2u64),
            ("game.chess.d.Reverse".to_string(), 1u64),
        ];
        let s = read_stats(&counters, GameType::Chess, "Reverse");
        assert_eq!((s.wins, s.losses, s.draws), (5, 2, 1));
        assert_eq!(s.points(), 34, "10*5 - 8*2");
        assert_eq!(s.rank(), "Bronze");

        // A different game type is a separate ladder (empty here).
        assert!(!read_stats(&counters, GameType::C4, "Reverse").any());

        // Losses alone floor points at 0.
        let loser = read_stats(&[("game.ttt.l.Sad".to_string(), 9)], GameType::Ttt, "Sad");
        assert_eq!(loser.points(), 0);

        assert_eq!(counter_key(GameType::C4, 'w', "Bob"), "game.c4.w.Bob");
    }

    // A win folds its delta into the immediate rank push (counter bump is deferred).
    #[test]
    fn delta_reflects_the_just_finished_game() {
        let counters = vec![("game.ttt.w.Win".to_string(), 3u64)];
        let winner = read_stats_with_delta(&counters, GameType::Ttt, "Win", Side::A, Some(Outcome::Win(Side::A)));
        assert_eq!(winner.wins, 4);
        let loser = read_stats_with_delta(&counters, GameType::Ttt, "Lose", Side::B, Some(Outcome::Win(Side::A)));
        assert_eq!(loser.losses, 1);
        // Casual (unranked) game: no delta.
        assert_eq!(read_stats_with_delta(&counters, GameType::Ttt, "Win", Side::A, None).wins, 3);
    }
}
