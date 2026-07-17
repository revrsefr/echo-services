//! The referee: strongly-typed game state and rules for tic-tac-toe, Connect Four
//! and chess. Where the C++ original modelled everything as strings ("ttt", "X",
//! "pending", a 9-char board), this uses enums so illegal states are
//! unrepresentable, the per-game dispatch is exhaustively checked by the compiler
//! (no silent fallthrough), sides/status flow as `Copy` with no allocation, and a
//! grid move mutates a fixed array in place instead of cloning a String. Chess
//! lives in `chess.rs`.

use crate::chess;

pub const C4_W: usize = 7;
pub const C4_H: usize = 6;
const C4_CELLS: usize = C4_W * C4_H;
const EMPTY: u8 = b' ';

const TTT_LINES: [[usize; 3]; 8] = [
    [0, 1, 2], [3, 4, 5], [6, 7, 8],
    [0, 3, 6], [1, 4, 7], [2, 5, 8],
    [0, 4, 8], [2, 4, 6],
];

/// Which game. `Copy`, so it flows without clones or string compares.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GameType {
    Ttt,
    C4,
    Chess,
}

impl GameType {
    pub fn from_arg(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "ttt" => Some(Self::Ttt),
            "c4" => Some(Self::C4),
            "chess" => Some(Self::Chess),
            _ => None,
        }
    }

    /// Wire/config token: the GS# `g=` field, the counter-key segment, the TOP arg.
    pub fn wire(self) -> &'static str {
        match self {
            Self::Ttt => "ttt",
            Self::C4 => "c4",
            Self::Chess => "chess",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Ttt => "Morpion",
            Self::C4 => "Puissance 4",
            Self::Chess => "Échecs",
        }
    }

    /// The piece/colour glyph a side plays; the challenger (A) moves first.
    fn glyph(self, side: Side) -> u8 {
        let (a, b) = match self {
            Self::Ttt => (b'X', b'O'),
            Self::C4 => (b'R', b'Y'),
            Self::Chess => (b'w', b'b'),
        };
        match side {
            Side::A => a,
            Side::B => b,
        }
    }

    fn side_of_glyph(self, glyph: u8) -> Side {
        if glyph == self.glyph(Side::A) {
            Side::A
        } else {
            Side::B
        }
    }
}

/// The two players. A is the challenger and always moves first.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Side {
    A,
    B,
}

impl Side {
    pub fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Pending,
    Active,
    Over,
}

impl Status {
    pub fn wire(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Over => "over",
        }
    }
}

/// How a finished game ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    Draw,
    Win(Side),
}

/// The board — also the single source of truth for the game kind. Grid games are
/// fixed byte arrays (`EMPTY` = free), so a move mutates in place with no alloc.
pub enum Board {
    Ttt([u8; 9]),
    C4([u8; C4_CELLS]),
    Chess(chess::State),
}

impl Board {
    fn new(gt: GameType) -> Self {
        match gt {
            GameType::Ttt => Self::Ttt([EMPTY; 9]),
            GameType::C4 => Self::C4([EMPTY; C4_CELLS]),
            GameType::Chess => Self::Chess(chess::initial()),
        }
    }

    pub fn gtype(&self) -> GameType {
        match self {
            Self::Ttt(_) => GameType::Ttt,
            Self::C4(_) => GameType::C4,
            Self::Chess(_) => GameType::Chess,
        }
    }

    fn grid(&self) -> Option<&[u8]> {
        match self {
            Self::Ttt(c) => Some(c),
            Self::C4(c) => Some(c),
            Self::Chess(_) => None,
        }
    }

    /// Space-free wire form: grid empty cells become '.', chess a comma-FEN.
    fn encode(&self) -> String {
        match self {
            Self::Chess(st) => chess::encode(st),
            _ => self
                .grid()
                .unwrap()
                .iter()
                .map(|&b| if b == EMPTY { '.' } else { b as char })
                .collect(),
        }
    }
}

/// One live game. `acc_*`/`nick_*` are the ranked identity and current nick of
/// each side; A is the challenger. The board carries the game kind, so `gtype()`
/// derives from it — no separate field to keep consistent.
pub struct Game {
    pub id: u64,
    pub acc_a: String,
    pub acc_b: String,
    pub nick_a: String,
    pub nick_b: String,
    pub a_reg: bool,
    pub b_reg: bool,
    pub board: Board,
    pub turn: Side,
    pub status: Status,
    pub result: Option<Outcome>,
}

impl Game {
    #[allow(clippy::too_many_arguments)]
    pub fn new(id: u64, gt: GameType, acc_a: String, a_reg: bool, acc_b: String, b_reg: bool, nick_a: String, nick_b: String) -> Self {
        Self {
            id,
            acc_a,
            acc_b,
            nick_a,
            nick_b,
            a_reg,
            b_reg,
            board: Board::new(gt),
            turn: Side::A,
            status: Status::Pending,
            result: None,
        }
    }

    pub fn gtype(&self) -> GameType {
        self.board.gtype()
    }

    /// Space-free board for the wire.
    pub fn encode(&self) -> String {
        self.board.encode()
    }

    /// The glyph the given side plays (GS# `t=`/`me=`).
    pub fn glyph(&self, side: Side) -> char {
        self.gtype().glyph(side) as char
    }
}

/// Apply `mv` for `side`; returns true iff it was legal and applied (mutating the
/// board and advancing the turn). Rejects out-of-turn and illegal moves.
pub fn apply_move(g: &mut Game, side: Side, mv: &str) -> bool {
    if g.turn != side {
        return false;
    }
    let glyph = g.gtype().glyph(side);
    match &mut g.board {
        Board::Ttt(cells) => {
            let Ok(c) = mv.parse::<usize>() else { return false };
            if c >= cells.len() || cells[c] != EMPTY {
                return false;
            }
            cells[c] = glyph;
        }
        Board::C4(cells) => {
            let Ok(col) = mv.parse::<usize>() else { return false };
            if col >= C4_W {
                return false;
            }
            // row 0 = bottom; the piece drops to the lowest empty cell.
            match (0..C4_H).map(|r| r * C4_W + col).find(|&i| cells[i] == EMPTY) {
                Some(i) => cells[i] = glyph,
                None => return false, // column full
            }
        }
        Board::Chess(st) => {
            let Some(m) = chess::parse(st, mv) else { return false };
            *st = chess::apply(st, &m);
            // Chess owns the side to move; keep the game turn in step with it.
            g.turn = if st.turn == b'w' { Side::A } else { Side::B };
            return true;
        }
    }
    g.turn = side.other();
    true
}

/// `None` while the game is ongoing, else how it ended.
pub fn terminal(g: &Game) -> Option<Outcome> {
    match &g.board {
        Board::Ttt(b) => {
            for ln in TTT_LINES {
                let a = b[ln[0]];
                if a != EMPTY && a == b[ln[1]] && a == b[ln[2]] {
                    return Some(Outcome::Win(GameType::Ttt.side_of_glyph(a)));
                }
            }
            full_or_ongoing(b)
        }
        Board::C4(b) => {
            let dirs: [(i32, i32); 4] = [(1, 0), (0, 1), (1, 1), (1, -1)];
            for c in 0..C4_W as i32 {
                for r in 0..C4_H as i32 {
                    let p = b[r as usize * C4_W + c as usize];
                    if p == EMPTY {
                        continue;
                    }
                    for (dc, dr) in dirs {
                        let (mut cc, mut rr) = (c, r);
                        let run = (0..4).all(|_| {
                            let ok = (0..C4_W as i32).contains(&cc)
                                && (0..C4_H as i32).contains(&rr)
                                && b[rr as usize * C4_W + cc as usize] == p;
                            cc += dc;
                            rr += dr;
                            ok
                        });
                        if run {
                            return Some(Outcome::Win(GameType::C4.side_of_glyph(p)));
                        }
                    }
                }
            }
            full_or_ongoing(b)
        }
        Board::Chess(st) => match chess::over(st).as_str() {
            "w" => Some(Outcome::Win(Side::A)),
            "b" => Some(Outcome::Win(Side::B)),
            "draw" => Some(Outcome::Draw),
            _ => None,
        },
    }
}

fn full_or_ongoing(cells: &[u8]) -> Option<Outcome> {
    if cells.iter().all(|&c| c != EMPTY) {
        Some(Outcome::Draw)
    } else {
        None
    }
}

// IRCv3 message-tag value escaping. The state TAGMSG is built as a raw line and
// the serializer only strips CR/LF/NUL, so a space or ';' in the value would
// corrupt the s2s line (it once netsplit services under Anope). Escape it here.
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

    fn game(gt: GameType) -> Game {
        Game::new(1, gt, "a".into(), true, "b".into(), true, "a".into(), "b".into())
    }

    #[test]
    fn ttt_rejects_out_of_turn_and_occupied_and_detects_a_win() {
        let mut g = game(GameType::Ttt);
        assert!(!apply_move(&mut g, Side::B, "0"), "not B's turn");
        assert!(apply_move(&mut g, Side::A, "0"));
        assert!(!apply_move(&mut g, Side::A, "0"), "cell taken");
        assert!(!apply_move(&mut g, Side::B, "9"), "off board");
        apply_move(&mut g, Side::B, "3");
        apply_move(&mut g, Side::A, "1");
        apply_move(&mut g, Side::B, "4");
        assert_eq!(terminal(&g), None);
        assert!(apply_move(&mut g, Side::A, "2"));
        assert_eq!(terminal(&g), Some(Outcome::Win(Side::A)), "top row wins for A (X)");
    }

    #[test]
    fn c4_drops_to_bottom_and_detects_vertical_win() {
        let mut g = game(GameType::C4);
        for _ in 0..3 {
            assert!(apply_move(&mut g, Side::A, "3"));
            assert_eq!(terminal(&g), None);
            assert!(apply_move(&mut g, Side::B, "4"));
        }
        assert!(apply_move(&mut g, Side::A, "3"));
        assert_eq!(terminal(&g), Some(Outcome::Win(Side::A)), "four in a column wins");
        assert_eq!(&g.encode()[3..4], "R", "the pieces fell to the bottom of column 3");
    }

    #[test]
    fn chess_plays_a_legal_move_and_rejects_an_illegal_one() {
        let mut g = game(GameType::Chess);
        assert!(!apply_move(&mut g, Side::B, "e7e5"), "white (A) to move");
        assert!(apply_move(&mut g, Side::A, "e2e4"));
        assert_eq!(g.turn, Side::B);
        assert!(!apply_move(&mut g, Side::B, "e7e9"), "off board / illegal");
        assert!(apply_move(&mut g, Side::B, "e7e5"));
        assert_eq!(terminal(&g), None, "game ongoing");
    }

    #[test]
    fn encode_is_space_free_and_tags_escape() {
        let g = game(GameType::Ttt);
        assert!(!g.encode().contains(' '), "ttt empty cells become dots");
        assert_eq!(escape_tag("GS# 1 g=ttt"), "GS#\\s1\\sg=ttt");
    }
}
