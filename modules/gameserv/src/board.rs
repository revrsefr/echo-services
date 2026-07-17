//! The referee: game state and the per-game rules for tic-tac-toe, Connect Four
//! and chess. GameServ validates every move here and decides the winner, so a
//! client can never cheat (the board never leaves the server except as a signed
//! state line the web client only renders). Chess lives in `chess.rs`.

use crate::chess;

const TTT_LINES: [[usize; 3]; 8] = [
    [0, 1, 2], [3, 4, 5], [6, 7, 8],
    [0, 3, 6], [1, 4, 7], [2, 5, 8],
    [0, 4, 8], [2, 4, 6],
];
pub const C4_W: usize = 7;
pub const C4_H: usize = 6;

// One live game. `acc_*` is the ranked identity (account name, or the nick for a
// guest); `side_*` is the piece/colour each side plays. A = challenger, moves first.
pub struct Game {
    pub id: u64,
    pub gtype: String,        // "ttt" | "c4" | "chess"
    pub acc_a: String,
    pub acc_b: String,
    pub nick_a: String,
    pub nick_b: String,
    pub a_reg: bool,
    pub b_reg: bool,
    pub side_a: String,
    pub side_b: String,
    pub board: String,
    pub turn: String,         // side to move
    pub status: String,       // "pending" | "active" | "over"
    pub result: String,       // "" | "<winner account>" | "draw"
}

// One (account, game type) ladder row, materialised from the shared stat counters
// (`game.<type>.<w|l|d>.<account>`) that StatServ already persists. A player can be
// Gold at chess and Bronze at Connect Four, so each type keeps its own record.
#[derive(Default, Clone)]
pub struct Stats {
    pub wins: u32,
    pub losses: u32,
    pub draws: u32,
}

impl Stats {
    // Points are DERIVED from the win/loss counts (draws don't score), floored at
    // 0: win +10, loss -8. Deriving keeps the ladder to monotonic w/l/d counters,
    // so it rides StatServ's existing counter persistence with nothing to sync.
    pub fn points(&self) -> i32 {
        (10 * self.wins as i32 - 8 * self.losses as i32).max(0)
    }

    pub fn rank(&self) -> &'static str {
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

    pub fn any(&self) -> bool {
        self.wins > 0 || self.losses > 0 || self.draws > 0
    }
}

pub fn valid_type(t: &str) -> bool {
    matches!(t, "ttt" | "c4" | "chess")
}

pub fn type_label(t: &str) -> &'static str {
    match t {
        "chess" => "Échecs",
        "c4" => "Puissance 4",
        "ttt" => "Morpion",
        _ => "?",
    }
}

// The two sides for a game type; the challenger takes the first, moves first.
pub fn sides(gtype: &str) -> (&'static str, &'static str) {
    match gtype {
        "ttt" => ("X", "O"),
        "c4" => ("R", "Y"),
        _ => ("w", "b"),
    }
}

pub fn init_board(gtype: &str) -> String {
    match gtype {
        "ttt" => " ".repeat(9),
        "c4" => " ".repeat(C4_W * C4_H),
        "chess" => chess::encode(&chess::initial()),
        _ => String::new(),
    }
}

// Apply `mv` for `side`; returns true iff it was legal and applied (mutating the
// board and flipping the turn). Rejects out-of-turn and illegal moves.
pub fn apply_move(g: &mut Game, side: &str, mv: &str) -> bool {
    if g.turn != side {
        return false;
    }
    let other = if side == g.side_a { g.side_b.clone() } else { g.side_a.clone() };
    match g.gtype.as_str() {
        "ttt" => {
            let c: i32 = mv.parse().unwrap_or(-1);
            let mut b = g.board.clone().into_bytes();
            if !(0..=8).contains(&c) || b[c as usize] != b' ' {
                return false;
            }
            b[c as usize] = side.as_bytes()[0];
            g.board = String::from_utf8(b).unwrap_or_default();
            g.turn = other;
            true
        }
        "c4" => {
            let col: i32 = mv.parse().unwrap_or(-1);
            if col < 0 || col as usize >= C4_W {
                return false;
            }
            let col = col as usize;
            let mut b = g.board.clone().into_bytes();
            for r in 0..C4_H {
                // row 0 = bottom; the piece drops to the lowest empty cell.
                let i = r * C4_W + col;
                if b[i] == b' ' {
                    b[i] = side.as_bytes()[0];
                    g.board = String::from_utf8(b).unwrap_or_default();
                    g.turn = other;
                    return true;
                }
            }
            false // column full
        }
        "chess" => {
            let st = chess::decode(&g.board);
            match chess::parse(&st, mv) {
                Some(m) => {
                    let ns = chess::apply(&st, &m);
                    g.board = chess::encode(&ns);
                    g.turn = (ns.turn as char).to_string();
                    true
                }
                None => false,
            }
        }
        _ => false,
    }
}

// "" = ongoing, "draw", or the winning side string.
pub fn terminal(g: &Game) -> String {
    match g.gtype.as_str() {
        "ttt" => {
            let b = g.board.as_bytes();
            for ln in TTT_LINES {
                let a = b[ln[0]];
                if a != b' ' && a == b[ln[1]] && a == b[ln[2]] {
                    return (a as char).to_string();
                }
            }
            if g.board.contains(' ') { String::new() } else { "draw".into() }
        }
        "c4" => {
            let b = g.board.as_bytes();
            let dirs: [(i32, i32); 4] = [(1, 0), (0, 1), (1, 1), (1, -1)];
            for c in 0..C4_W as i32 {
                for r in 0..C4_H as i32 {
                    let p = b[r as usize * C4_W + c as usize];
                    if p == b' ' {
                        continue;
                    }
                    for (dc, dr) in dirs {
                        let (mut cc, mut rr) = (c, r);
                        let mut ok = true;
                        for _ in 0..4 {
                            if cc < 0 || cc >= C4_W as i32 || rr < 0 || rr >= C4_H as i32
                                || b[rr as usize * C4_W + cc as usize] != p
                            {
                                ok = false;
                                break;
                            }
                            cc += dc;
                            rr += dr;
                        }
                        if ok {
                            return (p as char).to_string();
                        }
                    }
                }
            }
            if g.board.contains(' ') { String::new() } else { "draw".into() }
        }
        "chess" => chess::over(&chess::decode(&g.board)),
        _ => String::new(),
    }
}

// The board rendered space-free for the wire: chess is already a comma-FEN;
// ttt/c4 map empty cells ' ' -> '.'.
pub fn encode_board(g: &Game) -> String {
    if g.gtype == "chess" {
        g.board.clone()
    } else {
        g.board.replace(' ', ".")
    }
}

// IRCv3 message-tag value escaping. We build the state TAGMSG as a raw line, and
// the serializer only strips CR/LF/NUL — so a space or ';' in the value would
// corrupt the s2s line (it once caused a netsplit under Anope). Escape here.
pub fn escape_tag(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            ';' => out.push_str("\\:"),
            ' ' => out.push_str("\\s"),
            '\\' => out.push_str("\\\\"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn game(gtype: &str) -> Game {
        let (sa, sb) = sides(gtype);
        Game {
            id: 1, gtype: gtype.into(), acc_a: "a".into(), acc_b: "b".into(),
            nick_a: "a".into(), nick_b: "b".into(), a_reg: true, b_reg: true,
            side_a: sa.into(), side_b: sb.into(), board: init_board(gtype),
            turn: sa.into(), status: "active".into(), result: String::new(),
        }
    }

    #[test]
    fn ttt_rejects_out_of_turn_and_occupied_and_detects_a_win() {
        let mut g = game("ttt");
        // O can't move first (X's turn); an out-of-range/occupied cell is rejected.
        assert!(!apply_move(&mut g, "O", "0"), "not O's turn");
        assert!(apply_move(&mut g, "X", "0"));
        assert!(!apply_move(&mut g, "X", "0"), "cell taken");
        assert!(!apply_move(&mut g, "O", "9"), "off board");
        // X top row: 0,1,2 with O elsewhere.
        apply_move(&mut g, "O", "3");
        apply_move(&mut g, "X", "1");
        apply_move(&mut g, "O", "4");
        assert_eq!(terminal(&g), "");
        assert!(apply_move(&mut g, "X", "2"));
        assert_eq!(terminal(&g), "X", "top row wins");
    }

    #[test]
    fn c4_drops_to_bottom_and_detects_vertical_win() {
        let mut g = game("c4");
        // R stacks column 3; Y answers in column 4. Four R vertically wins.
        for _ in 0..3 {
            assert!(apply_move(&mut g, "R", "3"));
            assert_eq!(terminal(&g), "");
            assert!(apply_move(&mut g, "Y", "4"));
        }
        assert!(apply_move(&mut g, "R", "3"));
        assert_eq!(terminal(&g), "R", "four in a column wins");
        // The pieces fell to the bottom of column 3 (rows 0..3).
        assert_eq!(&g.board[3..4], "R");
    }

    #[test]
    fn chess_plays_a_legal_move_and_rejects_an_illegal_one() {
        let mut g = game("chess");
        assert!(!apply_move(&mut g, "b", "e7e5"), "white to move");
        assert!(apply_move(&mut g, "w", "e2e4"));
        assert_eq!(g.turn, "b");
        assert!(!apply_move(&mut g, "b", "e7e9"), "off board / illegal");
        assert!(apply_move(&mut g, "b", "e7e5"));
        assert_eq!(terminal(&g), "", "game ongoing");
    }

    #[test]
    fn encode_board_is_space_free() {
        let g = game("ttt");
        assert!(!encode_board(&g).contains(' '), "ttt empty cells become dots");
        assert_eq!(escape_tag("GS# 1 g=ttt"), "GS#\\s1\\sg=ttt");
    }
}
