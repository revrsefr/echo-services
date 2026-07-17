//! Self-contained chess engine for the GameServ referee.
//!
//! Pure-logic port of the perft-verified `gschess` C++ engine (no I/O, no
//! external crates). Board is 64 bytes, index = rank*8 + file
//! (a1=0, h1=7, a8=56, h8=63), `b' '` = empty, pieces `PNBRQK` (white) /
//! `pnbrqk` (black). The wire form ([`encode`]/[`decode`]) is a comma-separated
//! FEN so it carries no spaces: `"<rows>,<turn>,<castling>,<ep>"`.

const EMPTY: u8 = b' ';

#[inline]
fn cf(s: i32) -> i32 {
    s & 7
}

#[inline]
fn cr(s: i32) -> i32 {
    s >> 3
}

#[inline]
fn csq(f: i32, r: i32) -> i32 {
    r * 8 + f
}

/// Colour of a piece byte: `b'w'` for uppercase (white), `b'b'` otherwise.
#[inline]
fn ccolor(p: u8) -> u8 {
    if p.is_ascii_uppercase() {
        b'w'
    } else {
        b'b'
    }
}

/// True if `p` is a non-empty piece owned by colour `c`.
#[inline]
fn cown(p: u8, c: u8) -> bool {
    p != EMPTY && ccolor(p) == c
}

#[inline]
fn upper(p: u8) -> u8 {
    p.to_ascii_uppercase()
}

const KN: [(i32, i32); 8] = [
    (1, 2),
    (2, 1),
    (2, -1),
    (1, -2),
    (-1, -2),
    (-2, -1),
    (-2, 1),
    (-1, 2),
];
const KG: [(i32, i32); 8] = [
    (1, 0),
    (1, 1),
    (0, 1),
    (-1, 1),
    (-1, 0),
    (-1, -1),
    (0, -1),
    (1, -1),
];
const BD: [(i32, i32); 4] = [(1, 1), (-1, 1), (-1, -1), (1, -1)];
const RD: [(i32, i32); 4] = [(1, 0), (-1, 0), (0, 1), (0, -1)];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Move {
    pub from: usize,
    pub to: usize,
    /// 0 or `b'q'` / `b'r'` / `b'b'` / `b'n'`.
    pub promo: u8,
    /// en-passant capture
    pub ep: bool,
    /// pawn double-push
    pub dbl: bool,
    /// 0, `b'K'` or `b'Q'`
    pub castle: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    /// 64 bytes, index = rank*8 + file.
    pub board: [u8; 64],
    /// `b'w'` or `b'b'`.
    pub turn: u8,
    /// White king-side castling right.
    pub c_k: bool,
    /// White queen-side castling right.
    pub c_q: bool,
    /// Black king-side castling right.
    pub c_k_black: bool,
    /// Black queen-side castling right.
    pub c_q_black: bool,
    /// En-passant target square, -1 = none.
    pub ep: i32,
}

impl Default for State {
    fn default() -> Self {
        State {
            board: [EMPTY; 64],
            turn: b'w',
            c_k: true,
            c_q: true,
            c_k_black: true,
            c_q_black: true,
            ep: -1,
        }
    }
}

pub fn initial() -> State {
    let mut st = State::default();
    let back = b"RNBQKBNR";
    for f in 0..8 {
        st.board[csq(f, 0) as usize] = back[f as usize];
        st.board[csq(f, 1) as usize] = b'P';
        st.board[csq(f, 6) as usize] = b'p';
        st.board[csq(f, 7) as usize] = back[f as usize].to_ascii_lowercase();
    }
    st
}

/// True if square `target` is attacked by any piece of colour `by`.
fn attacked(b: &[u8; 64], target: i32, by: u8) -> bool {
    let tf = cf(target);
    let tr = cr(target);
    let pr = if by == b'w' { tr - 1 } else { tr + 1 };

    // Pawn attacks (a pawn of colour `by` on `pr` attacking diagonally).
    for df in [-1, 1] {
        let f = tf + df;
        if (0..8).contains(&f) && (0..8).contains(&pr) {
            let p = b[csq(f, pr) as usize];
            if p != EMPTY && ccolor(p) == by && upper(p) == b'P' {
                return true;
            }
        }
    }
    // Knight attacks.
    for (dx, dy) in KN {
        let f = tf + dx;
        let r = tr + dy;
        if (0..8).contains(&f) && (0..8).contains(&r) {
            let p = b[csq(f, r) as usize];
            if p != EMPTY && ccolor(p) == by && upper(p) == b'N' {
                return true;
            }
        }
    }
    // King attacks.
    for (dx, dy) in KG {
        let f = tf + dx;
        let r = tr + dy;
        if (0..8).contains(&f) && (0..8).contains(&r) {
            let p = b[csq(f, r) as usize];
            if p != EMPTY && ccolor(p) == by && upper(p) == b'K' {
                return true;
            }
        }
    }
    // Bishop / queen (diagonal) attacks.
    for (dx, dy) in BD {
        let mut f = tf + dx;
        let mut r = tr + dy;
        while (0..8).contains(&f) && (0..8).contains(&r) {
            let p = b[csq(f, r) as usize];
            if p != EMPTY {
                let u = upper(p);
                if ccolor(p) == by && (u == b'B' || u == b'Q') {
                    return true;
                }
                break;
            }
            f += dx;
            r += dy;
        }
    }
    // Rook / queen (orthogonal) attacks.
    for (dx, dy) in RD {
        let mut f = tf + dx;
        let mut r = tr + dy;
        while (0..8).contains(&f) && (0..8).contains(&r) {
            let p = b[csq(f, r) as usize];
            if p != EMPTY {
                let u = upper(p);
                if ccolor(p) == by && (u == b'R' || u == b'Q') {
                    return true;
                }
                break;
            }
            f += dx;
            r += dy;
        }
    }
    false
}

fn king_sq(b: &[u8; 64], c: u8) -> i32 {
    let k = if c == b'w' { b'K' } else { b'k' };
    b.iter().position(|&p| p == k).map(|i| i as i32).unwrap_or(-1)
}

fn in_check(st: &State, c: u8) -> bool {
    let by = if c == b'w' { b'b' } else { b'w' };
    attacked(&st.board, king_sq(&st.board, c), by)
}

fn add_pawn(mv: &mut Vec<Move>, from: i32, to: i32, promo: bool, ep: bool, dbl: bool) {
    if promo {
        for pr in *b"qrbn" {
            mv.push(Move {
                from: from as usize,
                to: to as usize,
                promo: pr,
                ..Move::default()
            });
        }
    } else {
        mv.push(Move {
            from: from as usize,
            to: to as usize,
            ep,
            dbl,
            ..Move::default()
        });
    }
}

/// Pseudo-legal moves (may leave the mover's own king in check).
fn pseudo(st: &State) -> Vec<Move> {
    let mut mv = Vec::new();
    let c = st.turn;
    let dir = if c == b'w' { 1 } else { -1 };
    let start_rank = if c == b'w' { 1 } else { 6 };
    let promo_rank = if c == b'w' { 7 } else { 0 };

    for s in 0..64 {
        let p = st.board[s as usize];
        if p == EMPTY || ccolor(p) != c {
            continue;
        }
        let f = cf(s);
        let r = cr(s);
        let t = upper(p);
        if t == b'P' {
            let r1 = r + dir;
            if (0..8).contains(&r1) && st.board[csq(f, r1) as usize] == EMPTY {
                add_pawn(&mut mv, s, csq(f, r1), r1 == promo_rank, false, false);
                if r == start_rank && st.board[csq(f, r + 2 * dir) as usize] == EMPTY {
                    add_pawn(&mut mv, s, csq(f, r + 2 * dir), false, false, true);
                }
            }
            for df in [-1, 1] {
                let cf2 = f + df;
                let cr2 = r + dir;
                if !(0..8).contains(&cf2) || !(0..8).contains(&cr2) {
                    continue;
                }
                let to = csq(cf2, cr2);
                let tp = st.board[to as usize];
                if tp != EMPTY && ccolor(tp) != c {
                    add_pawn(&mut mv, s, to, cr2 == promo_rank, false, false);
                } else if to == st.ep {
                    mv.push(Move {
                        from: s as usize,
                        to: to as usize,
                        ep: true,
                        ..Move::default()
                    });
                }
            }
        } else if t == b'N' {
            for (dx, dy) in KN {
                let cf2 = f + dx;
                let cr2 = r + dy;
                if !(0..8).contains(&cf2) || !(0..8).contains(&cr2) {
                    continue;
                }
                let to = csq(cf2, cr2);
                if !cown(st.board[to as usize], c) {
                    mv.push(Move {
                        from: s as usize,
                        to: to as usize,
                        ..Move::default()
                    });
                }
            }
        } else if t == b'K' {
            for (dx, dy) in KG {
                let cf2 = f + dx;
                let cr2 = r + dy;
                if !(0..8).contains(&cf2) || !(0..8).contains(&cr2) {
                    continue;
                }
                let to = csq(cf2, cr2);
                if !cown(st.board[to as usize], c) {
                    mv.push(Move {
                        from: s as usize,
                        to: to as usize,
                        ..Move::default()
                    });
                }
            }
            let enemy = if c == b'w' { b'b' } else { b'w' };
            let rank = if c == b'w' { 0 } else { 7 };
            let k_from = csq(4, rank);
            if s == k_from && !attacked(&st.board, k_from, enemy) {
                let kr = if c == b'w' { st.c_k } else { st.c_k_black };
                let qr = if c == b'w' { st.c_q } else { st.c_q_black };
                let rook = if c == b'w' { b'R' } else { b'r' };
                if kr
                    && st.board[csq(5, rank) as usize] == EMPTY
                    && st.board[csq(6, rank) as usize] == EMPTY
                    && st.board[csq(7, rank) as usize] == rook
                    && !attacked(&st.board, csq(5, rank), enemy)
                    && !attacked(&st.board, csq(6, rank), enemy)
                {
                    mv.push(Move {
                        from: k_from as usize,
                        to: csq(6, rank) as usize,
                        castle: b'K',
                        ..Move::default()
                    });
                }
                if qr
                    && st.board[csq(3, rank) as usize] == EMPTY
                    && st.board[csq(2, rank) as usize] == EMPTY
                    && st.board[csq(1, rank) as usize] == EMPTY
                    && st.board[csq(0, rank) as usize] == rook
                    && !attacked(&st.board, csq(3, rank), enemy)
                    && !attacked(&st.board, csq(2, rank), enemy)
                {
                    mv.push(Move {
                        from: k_from as usize,
                        to: csq(2, rank) as usize,
                        castle: b'Q',
                        ..Move::default()
                    });
                }
            }
        } else {
            // Sliding pieces: bishop (BD), rook (RD), queen (both).
            let dirs: &[(i32, i32)] = match t {
                b'B' => &BD,
                b'R' => &RD,
                _ => &[BD[0], BD[1], BD[2], BD[3], RD[0], RD[1], RD[2], RD[3]],
            };
            for &(dx, dy) in dirs {
                let mut cf2 = f + dx;
                let mut cr2 = r + dy;
                while (0..8).contains(&cf2) && (0..8).contains(&cr2) {
                    let to = csq(cf2, cr2);
                    let tp = st.board[to as usize];
                    if tp != EMPTY {
                        if ccolor(tp) != c {
                            mv.push(Move {
                                from: s as usize,
                                to: to as usize,
                                ..Move::default()
                            });
                        }
                        break;
                    }
                    mv.push(Move {
                        from: s as usize,
                        to: to as usize,
                        ..Move::default()
                    });
                    cf2 += dx;
                    cr2 += dy;
                }
            }
        }
    }
    mv
}

pub fn apply(st: &State, m: &Move) -> State {
    let mut n = st.clone();
    let c = st.turn;
    let dir = if c == b'w' { 1 } else { -1 };
    let piece = n.board[m.from];
    n.board[m.from] = EMPTY;

    if m.ep {
        // Remove the pawn captured en passant: same file as target, same rank
        // as the moving pawn's origin.
        n.board[csq(cf(m.to as i32), cr(m.from as i32)) as usize] = EMPTY;
    }
    if m.promo != 0 {
        n.board[m.to] = if c == b'w' {
            m.promo.to_ascii_uppercase()
        } else {
            m.promo
        };
    } else {
        n.board[m.to] = piece;
    }
    if m.castle != 0 {
        let rk = if c == b'w' { 0 } else { 7 };
        let rook = if c == b'w' { b'R' } else { b'r' };
        if m.castle == b'K' {
            n.board[csq(7, rk) as usize] = EMPTY;
            n.board[csq(5, rk) as usize] = rook;
        } else {
            n.board[csq(0, rk) as usize] = EMPTY;
            n.board[csq(3, rk) as usize] = rook;
        }
    }

    let pu = upper(piece);
    if pu == b'K' {
        if c == b'w' {
            n.c_k = false;
            n.c_q = false;
        } else {
            n.c_k_black = false;
            n.c_q_black = false;
        }
    }
    if piece == b'R' {
        if m.from == csq(0, 0) as usize {
            n.c_q = false;
        }
        if m.from == csq(7, 0) as usize {
            n.c_k = false;
        }
    }
    if piece == b'r' {
        if m.from == csq(0, 7) as usize {
            n.c_q_black = false;
        }
        if m.from == csq(7, 7) as usize {
            n.c_k_black = false;
        }
    }
    // Capturing a rook on its home square removes that castling right.
    if m.to == csq(0, 0) as usize {
        n.c_q = false;
    }
    if m.to == csq(7, 0) as usize {
        n.c_k = false;
    }
    if m.to == csq(0, 7) as usize {
        n.c_q_black = false;
    }
    if m.to == csq(7, 7) as usize {
        n.c_k_black = false;
    }

    n.turn = if c == b'w' { b'b' } else { b'w' };
    n.ep = if m.dbl {
        csq(cf(m.from as i32), cr(m.from as i32) + dir)
    } else {
        -1
    };
    n
}

/// Fully legal moves: pseudo-legal filtered so the mover's king is not left
/// attacked.
pub fn legal(st: &State) -> Vec<Move> {
    let c = st.turn;
    let by = if c == b'w' { b'b' } else { b'w' };
    pseudo(st)
        .into_iter()
        .filter(|m| {
            let ns = apply(st, m);
            !attacked(&ns.board, king_sq(&ns.board, c), by)
        })
        .collect()
}

/// `""` ongoing; `"draw"` for stalemate; or the winning side (`"w"`/`"b"`) on
/// checkmate.
pub fn over(st: &State) -> String {
    if !legal(st).is_empty() {
        return String::new();
    }
    if in_check(st, st.turn) {
        return if st.turn == b'w' { "b" } else { "w" }.to_string();
    }
    "draw".to_string()
}

fn name_sq(s: i32) -> String {
    let mut r = String::new();
    r.push((b'a' + cf(s) as u8) as char);
    r.push((b'1' + cr(s) as u8) as char);
    r
}

fn sq_name(n: &[u8]) -> i32 {
    csq((n[0] - b'a') as i32, (n[1] - b'1') as i32)
}

/// Find the legal move matching a UCI string (`e2e4`, `e7e8q`). `None` if not
/// legal.
pub fn parse(st: &State, uci: &str) -> Option<Move> {
    let bytes = uci.as_bytes();
    if bytes.len() < 4 {
        return None;
    }
    let from = sq_name(&bytes[0..2]) as usize;
    let to = sq_name(&bytes[2..4]) as usize;
    let promo = if bytes.len() > 4 {
        bytes[4].to_ascii_lowercase()
    } else {
        0
    };
    legal(st)
        .into_iter()
        .find(|m| m.from == from && m.to == to && m.promo == promo)
}

/// Comma-separated FEN (no spaces) for the wire.
pub fn encode(st: &State) -> String {
    let mut rows = String::new();
    for r in (0..8).rev() {
        let mut e = 0;
        let mut row = String::new();
        for f in 0..8 {
            let p = st.board[csq(f, r) as usize];
            if p != EMPTY {
                if e > 0 {
                    row.push_str(&e.to_string());
                    e = 0;
                }
                row.push(p as char);
            } else {
                e += 1;
            }
        }
        if e > 0 {
            row.push_str(&e.to_string());
        }
        if r < 7 {
            rows.push('/');
        }
        rows.push_str(&row);
    }
    let mut cc = String::new();
    if st.c_k {
        cc.push('K');
    }
    if st.c_q {
        cc.push('Q');
    }
    if st.c_k_black {
        cc.push('k');
    }
    if st.c_q_black {
        cc.push('q');
    }
    if cc.is_empty() {
        cc.push('-');
    }
    let ep = if st.ep < 0 {
        "-".to_string()
    } else {
        name_sq(st.ep)
    };
    format!("{},{},{},{}", rows, st.turn as char, cc, ep)
}

/// Inverse of [`encode`]. On malformed input (fewer than 4 comma parts) returns
/// [`initial`]. The referee keeps a live `State`, so this is only exercised by the
/// roundtrip test today — kept as part of the complete, perft-verified engine.
#[allow(dead_code)]
pub fn decode(enc: &str) -> State {
    let mut st = State {
        board: [EMPTY; 64],
        turn: b'w',
        c_k: false,
        c_q: false,
        c_k_black: false,
        c_q_black: false,
        ep: -1,
    };

    // Collect up to 4 comma-separated fields, mirroring the C++ manual scan:
    // each step takes the segment up to the next comma, or the whole remainder
    // when no comma is left.
    let mut parts: Vec<&str> = Vec::new();
    let mut pos = 0;
    while parts.len() < 4 {
        match enc[pos..].find(',') {
            Some(rel) => {
                let comma = pos + rel;
                parts.push(&enc[pos..comma]);
                pos = comma + 1;
            }
            None => {
                parts.push(&enc[pos..]);
                break;
            }
        }
    }
    if parts.len() < 4 {
        return initial();
    }

    // Board.
    let mut r: i32 = 7;
    let mut f: i32 = 0;
    for ch in parts[0].bytes() {
        if ch == b'/' {
            r -= 1;
            f = 0;
        } else if (b'1'..=b'8').contains(&ch) {
            f += (ch - b'0') as i32;
        } else {
            if (0..8).contains(&r) && (0..8).contains(&f) {
                st.board[csq(f, r) as usize] = ch;
            }
            f += 1;
        }
    }
    st.turn = parts[1].bytes().next().unwrap_or(b'w');
    for ch in parts[2].bytes() {
        match ch {
            b'K' => st.c_k = true,
            b'Q' => st.c_q = true,
            b'k' => st.c_k_black = true,
            b'q' => st.c_q_black = true,
            _ => {}
        }
    }
    st.ep = if parts[3] == "-" || parts[3].is_empty() {
        -1
    } else {
        sq_name(parts[3].as_bytes())
    };
    st
}

#[cfg(test)]
mod tests {
    use super::*;

    fn perft(st: &State, depth: u32) -> u64 {
        if depth == 0 {
            return 1;
        }
        let moves = legal(st);
        if depth == 1 {
            return moves.len() as u64;
        }
        moves.iter().map(|m| perft(&apply(st, m), depth - 1)).sum()
    }

    #[test]
    fn perft_start_position() {
        let st = initial();
        assert_eq!(perft(&st, 1), 20);
        assert_eq!(perft(&st, 2), 400);
        assert_eq!(perft(&st, 3), 8902);
        assert_eq!(perft(&st, 4), 197281);
    }

    #[test]
    fn encode_initial() {
        let enc = encode(&initial());
        assert_eq!(
            enc,
            "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR,w,KQkq,-"
        );
    }

    #[test]
    fn encode_decode_roundtrip() {
        let st = initial();
        assert_eq!(decode(&encode(&st)), st);
    }

    #[test]
    fn decode_malformed_returns_initial() {
        assert_eq!(decode("garbage"), initial());
        assert_eq!(decode("a,b,c"), initial());
    }

    #[test]
    fn parse_and_apply_e2e4() {
        let st = initial();
        let m = parse(&st, "e2e4").expect("e2e4 legal");
        assert!(m.dbl);
        let ns = apply(&st, &m);
        assert_eq!(ns.turn, b'b');
        assert_eq!(ns.ep, csq(4, 2)); // e3
        assert!(parse(&st, "e2e5").is_none());
    }
}
