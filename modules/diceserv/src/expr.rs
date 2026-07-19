//! A dice-and-math expression evaluator: tokenise, parse (recursive descent),
//! then evaluate — rolling dice as it goes and recording each roll for the
//! extended output. The reference ships its own Mersenne-Twister in C and a
//! shunting-yard parser with a variadic-argument hack; this is a plain typed AST
//! + the OS/`rand` generator, which is shorter and far easier to reason about.

use rand::Rng;

// Guardrails so a single expression can't ask us to roll forever.
const MAX_DICE: u64 = 99_999; // dice in one NdM roll
const MAX_SIDES: u64 = 99_999; // sides on a die
pub const MAX_TOTAL: u64 = 1_000_000; // dice rolled across the whole expression

// One resolved dice roll, kept for the extended (EX) output.
pub struct Roll {
    pub spec: String,     // e.g. "2d6"
    pub values: Vec<u64>, // each die's face
    pub total: u64,
}

pub struct Evaluated {
    pub value: f64,
    pub rolls: Vec<Roll>,
    pub total: u64, // dice rolled in this evaluation, for cross-repeat budgeting
}

// ---- tokens ----------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Num(f64),
    Ident(String), // includes the dice operator "d"/"D", constants, function names
    Op(char),      // + - * / % ^
    LParen,
    RParen,
    Comma,
}

fn tokenize(input: &str) -> Result<Vec<Tok>, String> {
    let chars: Vec<char> = input.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if c.is_ascii_digit() || (c == '.' && chars.get(i + 1).is_some_and(|d| d.is_ascii_digit())) {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                i += 1;
            }
            let s: String = chars[start..i].iter().collect();
            out.push(Tok::Num(s.parse().map_err(|_| format!("bad number '{s}'"))?));
        } else if c.is_ascii_alphabetic() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_alphabetic() {
                i += 1;
            }
            out.push(Tok::Ident(chars[start..i].iter().collect()));
        } else {
            match c {
                '+' | '-' | '*' | '/' | '%' | '^' => out.push(Tok::Op(c)),
                '(' | '[' | '{' => out.push(Tok::LParen),
                ')' | ']' | '}' => out.push(Tok::RParen),
                ',' => out.push(Tok::Comma),
                _ => return Err(format!("unexpected character '{c}'")),
            }
            i += 1;
        }
    }
    Ok(out)
}

// ---- AST -------------------------------------------------------------------

enum Ast {
    Num(f64),
    Neg(Box<Ast>),
    Bin(char, Box<Ast>, Box<Ast>),
    Dice(Box<Ast>, Box<Ast>),
    Func(String, Vec<Ast>),
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn is_dice(&self) -> bool {
        matches!(self.peek(), Some(Tok::Ident(s)) if s.eq_ignore_ascii_case("d"))
    }

    fn parse(mut self) -> Result<Ast, String> {
        let e = self.add()?;
        if self.pos != self.toks.len() {
            return Err("trailing characters in expression".to_string());
        }
        Ok(e)
    }

    fn add(&mut self) -> Result<Ast, String> {
        let mut left = self.mul()?;
        while let Some(Tok::Op(c @ ('+' | '-'))) = self.peek() {
            let c = *c;
            self.pos += 1;
            left = Ast::Bin(c, Box::new(left), Box::new(self.mul()?));
        }
        Ok(left)
    }

    fn mul(&mut self) -> Result<Ast, String> {
        let mut left = self.unary()?;
        loop {
            if let Some(Tok::Op(c @ ('*' | '/' | '%'))) = self.peek() {
                let c = *c;
                self.pos += 1;
                left = Ast::Bin(c, Box::new(left), Box::new(self.unary()?));
            } else if self.starts_atom() && !self.is_dice() {
                // Implicit multiplication: 2pi, 3(4), 2d6 2.
                left = Ast::Bin('*', Box::new(left), Box::new(self.unary()?));
            } else {
                return Ok(left);
            }
        }
    }

    // Whether the next token can begin an atom (for implicit multiplication).
    fn starts_atom(&self) -> bool {
        matches!(self.peek(), Some(Tok::Num(_) | Tok::Ident(_) | Tok::LParen))
    }

    fn unary(&mut self) -> Result<Ast, String> {
        match self.peek() {
            Some(Tok::Op('-')) => {
                self.pos += 1;
                Ok(Ast::Neg(Box::new(self.unary()?)))
            }
            Some(Tok::Op('+')) => {
                self.pos += 1;
                self.unary()
            }
            _ => self.pow(),
        }
    }

    fn pow(&mut self) -> Result<Ast, String> {
        let base = self.dice()?;
        if matches!(self.peek(), Some(Tok::Op('^'))) {
            self.pos += 1;
            // Right-associative, and the exponent may be signed (2^-3).
            return Ok(Ast::Bin('^', Box::new(base), Box::new(self.unary()?)));
        }
        Ok(base)
    }

    fn dice(&mut self) -> Result<Ast, String> {
        // A leading `d` means one die: d6 == 1d6.
        let mut left = if self.is_dice() { Ast::Num(1.0) } else { self.atom()? };
        while self.is_dice() {
            self.pos += 1;
            // `d%` is percentile — 100 sides.
            let sides = if matches!(self.peek(), Some(Tok::Op('%'))) {
                self.pos += 1;
                Ast::Num(100.0)
            } else {
                self.atom()?
            };
            left = Ast::Dice(Box::new(left), Box::new(sides));
        }
        Ok(left)
    }

    fn atom(&mut self) -> Result<Ast, String> {
        match self.peek().cloned() {
            Some(Tok::Num(n)) => {
                self.pos += 1;
                Ok(Ast::Num(n))
            }
            Some(Tok::LParen) => {
                self.pos += 1;
                let e = self.add()?;
                if !matches!(self.peek(), Some(Tok::RParen)) {
                    return Err("missing closing parenthesis".to_string());
                }
                self.pos += 1;
                Ok(e)
            }
            Some(Tok::Ident(name)) => {
                let lname = name.to_ascii_lowercase();
                self.pos += 1;
                match lname.as_str() {
                    "e" => Ok(Ast::Num(std::f64::consts::E)),
                    "pi" => Ok(Ast::Num(std::f64::consts::PI)),
                    _ if matches!(self.peek(), Some(Tok::LParen)) => {
                        self.pos += 1;
                        let mut args = vec![self.add()?];
                        while matches!(self.peek(), Some(Tok::Comma)) {
                            self.pos += 1;
                            args.push(self.add()?);
                        }
                        if !matches!(self.peek(), Some(Tok::RParen)) {
                            return Err(format!("missing ) after {lname}(...)"));
                        }
                        self.pos += 1;
                        Ok(Ast::Func(lname, args))
                    }
                    _ => Err(format!("unknown name '{name}'")),
                }
            }
            _ => Err("expected a value".to_string()),
        }
    }
}

// ---- evaluation ------------------------------------------------------------

// Evaluate a single expression (no repeat prefix), rolling dice via `rng`.
pub fn evaluate(input: &str, rng: &mut impl Rng) -> Result<Evaluated, String> {
    let toks = tokenize(input)?;
    if toks.is_empty() {
        return Err("nothing to roll".to_string());
    }
    // Bound the token count so a deeply-nested expression (e.g. thousands of `(`
    // or unary `-`) can't overflow the recursive-descent parser or `eval` and
    // crash the single-threaded daemon. Each nesting level needs >=1 token, so
    // this caps both recursion depths. Legit dice math is far shorter.
    const MAX_TOKENS: usize = 500;
    if toks.len() > MAX_TOKENS {
        return Err("that expression is too long".to_string());
    }
    let ast = Parser { toks, pos: 0 }.parse()?;
    let mut rolls = Vec::new();
    let mut total_dice = 0u64;
    let value = eval(&ast, rng, &mut rolls, &mut total_dice)?;
    if !value.is_finite() {
        return Err("that doesn't come out to a real number".to_string());
    }
    Ok(Evaluated { value, rolls, total: total_dice })
}

fn eval(ast: &Ast, rng: &mut impl Rng, rolls: &mut Vec<Roll>, total: &mut u64) -> Result<f64, String> {
    match ast {
        Ast::Num(n) => Ok(*n),
        Ast::Neg(a) => Ok(-eval(a, rng, rolls, total)?),
        Ast::Bin(op, a, b) => {
            let (x, y) = (eval(a, rng, rolls, total)?, eval(b, rng, rolls, total)?);
            Ok(match op {
                '+' => x + y,
                '-' => x - y,
                '*' => x * y,
                '/' => {
                    if y == 0.0 {
                        return Err("division by zero".to_string());
                    }
                    x / y
                }
                '%' => {
                    if y == 0.0 {
                        return Err("modulo by zero".to_string());
                    }
                    x % y
                }
                '^' => x.powf(y),
                _ => unreachable!(),
            })
        }
        Ast::Dice(n, m) => {
            let num = round_pos(eval(n, rng, rolls, total)?, "number of dice")?;
            let sides = round_pos(eval(m, rng, rolls, total)?, "sides")?;
            if num > MAX_DICE {
                return Err(format!("that's more than {MAX_DICE} dice"));
            }
            if sides > MAX_SIDES {
                return Err(format!("a die can't have more than {MAX_SIDES} sides"));
            }
            *total += num;
            if *total > MAX_TOTAL {
                return Err("that expression rolls too many dice".to_string());
            }
            // Retain at most MAX_KEPT individual faces for the extended (EX)
            // listing: a million-die roll is allowed for the total, but keeping
            // (and later stringifying) every face would be a multi-MB alloc under
            // the engine lock. The sum stays exact regardless.
            const MAX_KEPT: usize = 1000;
            let mut values = Vec::with_capacity((num as usize).min(MAX_KEPT));
            let mut sum = 0u64;
            for _ in 0..num {
                let face = rng.gen_range(1..=sides);
                if values.len() < MAX_KEPT {
                    values.push(face);
                }
                sum += face;
            }
            rolls.push(Roll { spec: format!("{num}d{sides}"), values, total: sum });
            Ok(sum as f64)
        }
        Ast::Func(name, args) => call(name, args, rng, rolls, total),
    }
}

// Round a value to a positive integer count (dice / sides must be >= 1).
fn round_pos(v: f64, what: &str) -> Result<u64, String> {
    if !v.is_finite() {
        return Err(format!("the {what} isn't a number"));
    }
    let n = v.round();
    if n < 1.0 {
        return Err(format!("the {what} must be at least 1"));
    }
    Ok(n as u64)
}

fn call(name: &str, args: &[Ast], rng: &mut impl Rng, rolls: &mut Vec<Roll>, total: &mut u64) -> Result<f64, String> {
    let mut v = Vec::with_capacity(args.len());
    for a in args {
        v.push(eval(a, rng, rolls, total)?);
    }
    let one = |v: &[f64]| -> Result<f64, String> {
        match v {
            [x] => Ok(*x),
            _ => Err(format!("{name}() takes one argument")),
        }
    };
    Ok(match name {
        "abs" => one(&v)?.abs(),
        "ceil" => one(&v)?.ceil(),
        "floor" => one(&v)?.floor(),
        "round" => one(&v)?.round(),
        "trunc" | "int" => one(&v)?.trunc(),
        "sqrt" => one(&v)?.sqrt(),
        "cbrt" => one(&v)?.cbrt(),
        "exp" => one(&v)?.exp(),
        "ln" | "log" => one(&v)?.ln(),
        "log10" => one(&v)?.log10(),
        "log2" => one(&v)?.log2(),
        "sin" => one(&v)?.sin(),
        "cos" => one(&v)?.cos(),
        "tan" => one(&v)?.tan(),
        "asin" => one(&v)?.asin(),
        "acos" => one(&v)?.acos(),
        "atan" => one(&v)?.atan(),
        "sinh" => one(&v)?.sinh(),
        "cosh" => one(&v)?.cosh(),
        "tanh" => one(&v)?.tanh(),
        "deg" => one(&v)?.to_degrees(),
        "rad" => one(&v)?.to_radians(),
        "sign" => one(&v)?.signum(),
        "min" if !v.is_empty() => v.into_iter().fold(f64::INFINITY, f64::min),
        "max" if !v.is_empty() => v.into_iter().fold(f64::NEG_INFINITY, f64::max),
        "hypot" => match v.as_slice() {
            [a, b] => a.hypot(*b),
            _ => return Err("hypot() takes two arguments".to_string()),
        },
        "pow" => match v.as_slice() {
            [a, b] => a.powf(*b),
            _ => return Err("pow() takes two arguments".to_string()),
        },
        _ => return Err(format!("unknown function '{name}'")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_nesting_is_rejected_not_a_stack_overflow() {
        let mut rng = rand::thread_rng();
        // Pathological deeply-nested / unary-heavy input must be refused by the
        // token cap, never overflow the recursive parser/eval and crash the daemon.
        assert!(evaluate(&"(".repeat(5000), &mut rng).is_err(), "deep parens rejected");
        assert!(evaluate(&"-".repeat(5000), &mut rng).is_err(), "deep unary rejected");
        // Ordinary expressions (including modest nesting) still evaluate.
        assert!(evaluate("2+3*4", &mut rng).is_ok());
        let nested = format!("{}1{}", "(".repeat(50), ")".repeat(50));
        assert!(evaluate(&nested, &mut rng).is_ok(), "modest nesting still parses");
    }

    #[test]
    fn extended_roll_retains_bounded_faces() {
        let mut rng = rand::thread_rng();
        // A huge roll is allowed for the total, but only a bounded number of faces
        // is kept for the extended listing (no multi-MB alloc under the lock).
        let ev = evaluate("50000d6", &mut rng).expect("large roll ok");
        assert_eq!(ev.rolls.len(), 1);
        assert!(ev.rolls[0].values.len() <= 1000, "faces retained are capped");
        assert!(ev.rolls[0].total >= 50000, "the sum stays exact");
    }
}
