//! DiceServ rolls dice and evaluates math expressions for tabletop games over
//! IRC. Stateless — a command parses an expression, rolls, and replies. ROLL/
//! CALC give the result (ROLL rounds to a whole number, CALC keeps decimals);
//! the EX variants also show each die. `N~expr` repeats a roll N times.

use fedserv_api::{NetView, Sender, Service, ServiceCtx, Store};

#[path = "expr.rs"]
mod expr;

const MAX_REPEATS: u32 = 25;

pub struct DiceServ {
    pub uid: String,
}

impl Service for DiceServ {
    fn nick(&self) -> &str {
        "DiceServ"
    }
    fn uid(&self) -> &str {
        &self.uid
    }
    fn gecos(&self) -> &str {
        "Dice Roller"
    }

    fn on_command(&mut self, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, _net: &dyn NetView, _db: &mut dyn Store) {
        let me = self.uid.as_str();
        match args.first().map(|s| s.to_ascii_uppercase()).as_deref() {
            Some("ROLL") => roll(me, from, &args[1..], ctx, false, true),
            Some("EXROLL") => roll(me, from, &args[1..], ctx, true, true),
            Some("CALC") => roll(me, from, &args[1..], ctx, false, false),
            Some("EXCALC") => roll(me, from, &args[1..], ctx, true, false),
            Some("HELP") | None => help(me, from, ctx),
            Some(other) => ctx.notice(me, from.uid, format!("I don't know \x02{other}\x02. Try \x02ROLL\x02, \x02CALC\x02, or \x02HELP\x02.")),
        }
    }
}

fn help(me: &str, from: &Sender, ctx: &mut ServiceCtx) {
    ctx.notice(me, from.uid, "DiceServ rolls dice and does maths. \x02ROLL\x02 <expr> (whole-number result), \x02CALC\x02 <expr> (keeps decimals), \x02EXROLL\x02/\x02EXCALC\x02 also show each die. Dice: \x022d6\x02, \x02d20\x02, \x02d%\x02. Also + - * / ^ %, parentheses, functions (sqrt, floor, min, …), \x02pi\x02/\x02e\x02, and \x023~2d6\x02 to repeat.");
}

fn roll(me: &str, from: &Sender, rest: &[&str], ctx: &mut ServiceCtx, extended: bool, round_result: bool) {
    let input = rest.join(" ");
    let input = input.trim();
    if input.is_empty() {
        ctx.notice(me, from.uid, "Give me something to roll, e.g. \x022d6+3\x02.");
        return;
    }
    // `N~expr` repeats the roll N times.
    let (times, body) = match input.split_once('~') {
        Some((n, body)) => match n.trim().parse::<u32>() {
            Ok(t) if (1..=MAX_REPEATS).contains(&t) => (t, body.trim()),
            _ => {
                ctx.notice(me, from.uid, format!("The repeat count before \x02~\x02 must be a number from 1 to {MAX_REPEATS}."));
                return;
            }
        },
        None => (1, input),
    };

    let mut rng = rand::thread_rng();
    for i in 0..times {
        match expr::evaluate(body, &mut rng) {
            Ok(ev) => {
                let result = format_value(ev.value, round_result);
                let prefix = if times > 1 { format!("[{}/{}] ", i + 1, times) } else { String::new() };
                let detail = if extended && !ev.rolls.is_empty() {
                    format!(" — {}", ev.rolls.iter().map(render_roll).collect::<Vec<_>>().join(", "))
                } else {
                    String::new()
                };
                ctx.notice(me, from.uid, format!("{prefix}\x02{body}\x02 = \x02{result}\x02{detail}"));
            }
            Err(why) => {
                ctx.notice(me, from.uid, format!("I couldn't roll \x02{body}\x02: {why}."));
                return; // the whole batch shares the expression, so it'll fail the same way
            }
        }
    }
}

// "2d6: 4+5=9" for the extended output.
fn render_roll(r: &expr::Roll) -> String {
    if r.values.len() == 1 {
        format!("{}: {}", r.spec, r.total)
    } else {
        let each = r.values.iter().map(u64::to_string).collect::<Vec<_>>().join("+");
        format!("{}: {}={}", r.spec, each, r.total)
    }
}

// ROLL rounds to a whole number; CALC keeps up to four decimals, trimmed.
fn format_value(v: f64, round_result: bool) -> String {
    if round_result {
        return format!("{}", v.round() as i64);
    }
    if v.fract() == 0.0 && v.abs() < 1e15 {
        return format!("{}", v as i64);
    }
    let s = format!("{v:.4}");
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

#[cfg(test)]
mod tests {
    use super::expr::evaluate;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn eval(s: &str) -> f64 {
        let mut rng = StdRng::seed_from_u64(1);
        evaluate(s, &mut rng).unwrap().value
    }

    #[test]
    fn arithmetic_and_precedence() {
        assert_eq!(eval("2+3*4"), 14.0);
        assert_eq!(eval("(2+3)*4"), 20.0);
        assert_eq!(eval("2^3^2"), 512.0); // right-associative
        assert_eq!(eval("-2^2"), -4.0); // unary looser than ^
        assert_eq!(eval("10%3"), 1.0);
        assert_eq!(eval("2pi/pi"), 2.0); // implicit multiplication + constant
        assert_eq!(eval("sqrt(16)+floor(3.9)"), 7.0);
        assert_eq!(eval("min(5,2,8)"), 2.0);
    }

    #[test]
    fn dice_stay_in_range() {
        let mut rng = StdRng::seed_from_u64(42);
        for _ in 0..200 {
            let ev = evaluate("3d6", &mut rng).unwrap();
            assert!((3.0..=18.0).contains(&ev.value), "3d6 out of range: {}", ev.value);
            assert_eq!(ev.rolls[0].values.len(), 3);
            assert!(ev.rolls[0].values.iter().all(|&f| (1..=6).contains(&f)));
        }
        // A leading d is one die; percentile is 1..=100.
        assert!((1.0..=20.0).contains(&evaluate("d20", &mut rng).unwrap().value));
        assert!((1.0..=100.0).contains(&evaluate("d%", &mut rng).unwrap().value));
    }

    #[test]
    fn rejects_bad_input_and_abuse() {
        let mut rng = StdRng::seed_from_u64(1);
        assert!(evaluate("2d6+", &mut rng).is_err());
        assert!(evaluate("1/0", &mut rng).is_err());
        assert!(evaluate("999999d6", &mut rng).is_err()); // too many dice
        assert!(evaluate("2d999999", &mut rng).is_err()); // too many sides
        assert!(evaluate("frobnicate(2)", &mut rng).is_err());
        assert!(evaluate("2 @ 3", &mut rng).is_err());
    }
}
