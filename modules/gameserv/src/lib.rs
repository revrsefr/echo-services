//! GameServ — a server-authoritative referee for tic-tac-toe, Connect Four and
//! chess, with a per-game ranked ladder. Every move is validated here and the
//! winner decided by the server, so a client can never cheat (see the hard rule:
//! games stay server-side). Players drive games entirely over `/msg GameServ`;
//! the machine-readable board is pushed to each player on an invisible client-only
//! TAGMSG (`+tchatou.fr/gs`) that only the web client renders — IRC clients see
//! just the human notices.
//!
//! `board.rs` is the referee (rules + state); `chess.rs` is the chess engine.

use std::collections::HashMap;

use echo_api::{HelpEntry, NetAction, NetView, Sender, Service, ServiceCtx, Store};

#[path = "chess.rs"]
mod chess;
#[path = "board.rs"]
mod board;

use board::{Game, Stats};

// Cap concurrent games per identity so a flood of never-finished challenges
// can't grow the map without bound (finished games are dropped immediately).
const MAX_GAMES_PER_USER: usize = 5;
const TYPES: [&str; 3] = ["chess", "c4", "ttt"];

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

// account key (lowercased) -> that player's ladder across game types.
type Ladder = HashMap<String, PlayerLadder>;

#[derive(Default)]
struct PlayerLadder {
    display: String,
    by_type: HashMap<String, Stats>,
}

pub struct GameServ {
    pub uid: String,
    games: HashMap<u64, Game>,
    ladder: Ladder,
    nextid: u64,
}

impl GameServ {
    pub fn new(uid: String) -> Self {
        Self { uid, games: HashMap::new(), ladder: Ladder::new(), nextid: 1 }
    }

    // A player's ranked identity: their account if registered, else their nick
    // (guests play casually under their nick; ranked points need an account).
    fn ident<'a>(from: &'a Sender) -> &'a str {
        from.account.unwrap_or(from.nick)
    }

    // Get (creating if needed) a mutable ladder row, remembering the display name.
    fn stat(&mut self, account: &str, gtype: &str) -> &mut Stats {
        let pl = self.ladder.entry(account.to_lowercase()).or_default();
        if pl.display.is_empty() {
            pl.display = account.to_string();
        }
        pl.by_type.entry(gtype.to_string()).or_default()
    }

    fn do_challenge(&mut self, me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView) {
        let (Some(&target), Some(&game)) = (args.get(1), args.get(2)) else {
            ctx.notice(me, from.uid, "Syntax: CHALLENGE <nick> <ttt|c4|chess>");
            return;
        };
        let gtype = game.to_lowercase();
        if !board::valid_type(&gtype) {
            ctx.notice(me, from.uid, "Unknown game. Available: \x02ttt\x02 (tic-tac-toe), \x02c4\x02 (Connect Four), \x02chess\x02.");
            return;
        }
        let Some(tuid) = net.uid_by_nick(target).map(str::to_string) else {
            ctx.notice(me, from.uid, format!("\x02{target}\x02 is not online."));
            return;
        };
        if tuid == from.uid {
            ctx.notice(me, from.uid, "You cannot challenge yourself.");
            return;
        }
        let meid = Self::ident(from).to_string();
        let mine = self.games.values().filter(|g| g.acc_a == meid || g.acc_b == meid).count();
        if mine >= MAX_GAMES_PER_USER {
            ctx.notice(me, from.uid, format!("You have too many games in progress (max {MAX_GAMES_PER_USER}). Finish or resign one first."));
            return;
        }
        let target_acc = net.account_of(&tuid).map(str::to_string);
        let (sa, sb) = board::sides(&gtype);
        let id = self.nextid;
        self.nextid += 1;
        let g = Game {
            id,
            gtype: gtype.clone(),
            acc_a: meid,
            a_reg: from.account.is_some(),
            acc_b: target_acc.clone().unwrap_or_else(|| target.to_string()),
            b_reg: target_acc.is_some(),
            nick_a: from.nick.to_string(),
            nick_b: target.to_string(),
            side_a: sa.to_string(),
            side_b: sb.to_string(),
            board: board::init_board(&gtype),
            turn: sa.to_string(),
            status: "pending".to_string(),
            result: String::new(),
        };
        self.games.insert(id, g);
        ctx.notice(me, from.uid, format!("Challenge \x02#{id}\x02 ({gtype}) sent to \x02{target}\x02."));
        ctx.notice(me, &tuid, format!("{} challenges you to {gtype} (game #{id}). \x02/msg GamesServ ACCEPT {id}\x02", from.nick));
        let g = &self.games[&id];
        push_one(g, 0, "pending", me, net, ctx); // challenger: waiting
        push_one(g, 1, "offer", me, net, ctx); // target: can accept/decline
    }

    fn do_accept(&mut self, me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView) {
        let meid = Self::ident(from).to_string();
        let id = match args.get(1) {
            Some(&s) => s.parse::<u64>().ok().filter(|id| self.games.get(id).is_some_and(|g| g.status == "pending" && g.acc_b == meid)),
            None => self.games.iter().find(|(_, g)| g.status == "pending" && g.acc_b == meid).map(|(id, _)| *id),
        };
        let Some(id) = id else {
            ctx.notice(me, from.uid, "No pending challenge to accept.");
            return;
        };
        let g = self.games.get_mut(&id).unwrap();
        g.status = "active".to_string();
        g.nick_b = from.nick.to_string();
        let side = g.side_b.clone();
        ctx.notice(me, from.uid, format!("Game \x02#{id}\x02 started. You are \x02{side}\x02."));
        push_state(&self.games[&id], me, net, ctx);
    }

    fn do_decline(&mut self, me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView) {
        let meid = Self::ident(from).to_string();
        let want: Option<u64> = args.get(1).and_then(|s| s.parse().ok());
        let id = self.games.iter().find(|(id, g)| {
            g.status == "pending" && g.acc_b == meid && want.is_none_or(|w| w == **id)
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
            if g.status != "active" || (g.acc_a != meid && g.acc_b != meid) {
                ctx.notice(me, from.uid, "No active game with that id.");
                return;
            }
            let side = if g.acc_a == meid { g.side_a.clone() } else { g.side_b.clone() };
            if g.acc_a == meid {
                g.nick_a = from.nick.to_string();
            } else {
                g.nick_b = from.nick.to_string();
            }
            if !board::apply_move(g, &side, mv) {
                ctx.notice(me, from.uid, "Illegal move (or not your turn).");
                return;
            }
            board::terminal(g)
        };
        if term.is_empty() {
            push_state(&self.games[&id], me, net, ctx);
        } else {
            self.finish(id, &term, me, net, ctx);
        }
    }

    fn do_resign(&mut self, me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView) {
        let Some(&ids) = args.get(1) else {
            ctx.notice(me, from.uid, "Syntax: RESIGN <id>");
            return;
        };
        let id: u64 = ids.parse().unwrap_or(0);
        let meid = Self::ident(from).to_string();
        let winner_side = match self.games.get(&id) {
            Some(g) if g.status == "active" && (g.acc_a == meid || g.acc_b == meid) => {
                if g.acc_a == meid { g.side_b.clone() } else { g.side_a.clone() }
            }
            _ => {
                ctx.notice(me, from.uid, "No active game with that id.");
                return;
            }
        };
        ctx.notice(me, from.uid, format!("You resigned game #{id}."));
        self.finish(id, &winner_side, me, net, ctx);
    }

    // End a game: record the result, update the ladder (only when BOTH players are
    // registered — casual guest games leave the ladder untouched), push the final
    // state + refreshed stats, and drop the game.
    fn finish(&mut self, id: u64, winner_side: &str, me: &str, net: &dyn NetView, ctx: &mut ServiceCtx) {
        let Some(mut g) = self.games.remove(&id) else { return };
        g.status = "over".to_string();
        let a_won = winner_side != "draw" && winner_side == g.side_a;
        g.result = if winner_side == "draw" {
            "draw".to_string()
        } else if a_won {
            g.acc_a.clone()
        } else {
            g.acc_b.clone()
        };
        if g.a_reg && g.b_reg {
            if winner_side == "draw" {
                self.stat(&g.acc_a, &g.gtype).draws += 1;
                self.stat(&g.acc_b, &g.gtype).draws += 1;
            } else {
                let (wacc, lacc) = if a_won { (g.acc_a.clone(), g.acc_b.clone()) } else { (g.acc_b.clone(), g.acc_a.clone()) };
                let w = self.stat(&wacc, &g.gtype);
                w.wins += 1;
                w.points += 10;
                let l = self.stat(&lacc, &g.gtype);
                l.losses += 1;
                l.points = (l.points - 8).max(0);
            }
        }
        push_state(&g, me, net, ctx);
        if g.a_reg {
            push_stats(&self.ladder, &g.acc_a, &g.nick_a, me, net, ctx);
        }
        if g.b_reg {
            push_stats(&self.ladder, &g.acc_b, &g.nick_b, me, net, ctx);
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
            ctx.notice(me, from.uid, format!("#{}  {}  vs {}  [{}]", g.id, g.gtype, opp, g.status));
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
        push_stats(&self.ladder, &who, from.nick, me, net, ctx); // machine lines for the UI
        ctx.notice(me, from.uid, format!("\x02{who}\x02 — classement Jeux"));
        let mut any = false;
        let pl = self.ladder.get(&who.to_lowercase());
        for ty in TYPES {
            if let Some(s) = pl.and_then(|p| p.by_type.get(ty)) {
                any = true;
                ctx.notice(me, from.uid, format!(
                    "  \x02{}\x02  \x02{}\x02 — {} pts ({}V {}D {}N)",
                    board::type_label(ty), s.rank(), s.points, s.wins, s.losses, s.draws
                ));
            }
        }
        if !any {
            ctx.notice(me, from.uid, "  (aucune partie classée pour l'instant)");
        }
    }

    fn do_top(&self, me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, net: &dyn NetView) {
        let ty = args.get(1).map(|s| s.to_lowercase()).unwrap_or_else(|| "chess".to_string());
        if !board::valid_type(&ty) {
            ctx.notice(me, from.uid, "Unknown game. Use \x02TOP ttt|c4|chess\x02.");
            return;
        }
        let mut all: Vec<(&str, &Stats)> = self.ladder.values()
            .filter_map(|pl| pl.by_type.get(&ty).filter(|s| s.points > 0).map(|s| (pl.display.as_str(), s)))
            .collect();
        all.sort_by_key(|&(_, s)| std::cmp::Reverse(s.points));
        push_tag(me, net, from.nick, &format!("GS$TOPSTART {ty}"), ctx);
        if all.is_empty() {
            ctx.notice(me, from.uid, format!("Classement \x02{}\x02 vide. Sois le premier à gagner !", board::type_label(&ty)));
            return;
        }
        ctx.notice(me, from.uid, format!("\x02Classement {} :\x02", board::type_label(&ty)));
        for (rank, (acc, s)) in all.iter().take(10).enumerate() {
            let rank = rank + 1;
            ctx.notice(me, from.uid, format!("{rank:2}. {acc:<16} {}  {} pts", s.rank(), s.points));
            push_tag(me, net, from.nick, &format!("GS$TOPROW {ty} {rank} {acc} {} {}", s.rank(), s.points), ctx);
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

// The GS# state line for one side (0 = A, 1 = B). `status_override` lets a
// challenge show as "pending" to the challenger and "offer" to the target.
fn push_one(g: &Game, s: usize, status_override: &str, me: &str, net: &dyn NetView, ctx: &mut ServiceCtx) {
    let (nick, side, oppnick, myacc) = if s == 0 {
        (&g.nick_a, &g.side_a, &g.nick_b, &g.acc_a)
    } else {
        (&g.nick_b, &g.side_b, &g.nick_a, &g.acc_b)
    };
    let status = if status_override.is_empty() { g.status.as_str() } else { status_override };
    let res = if g.status == "over" {
        if g.result == "draw" { "draw" } else if &g.result == myacc { "win" } else { "loss" }
    } else {
        "none"
    };
    let payload = format!(
        "GS# {} g={} s={} t={} me={} opp={} st={} r={}",
        g.id, g.gtype, board::encode_board(g), g.turn, side, oppnick, status, res
    );
    push_tag(me, net, nick, &payload, ctx);
}

fn push_state(g: &Game, me: &str, net: &dyn NetView, ctx: &mut ServiceCtx) {
    push_one(g, 0, "", me, net, ctx);
    push_one(g, 1, "", me, net, ctx);
}

// One GS$ stats line per game type (for the client's rank strip / profile badge).
fn push_stats(ladder: &Ladder, account: &str, to_nick: &str, me: &str, net: &dyn NetView, ctx: &mut ServiceCtx) {
    let pl = ladder.get(&account.to_lowercase());
    for ty in TYPES {
        let s = pl.and_then(|p| p.by_type.get(ty)).cloned().unwrap_or_default();
        let payload = format!("GS$ {} {} r={} p={} w={} l={} d={}", account, ty, s.rank(), s.points, s.wins, s.losses, s.draws);
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
