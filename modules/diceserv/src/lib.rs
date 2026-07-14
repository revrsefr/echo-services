//! DiceServ rolls dice and evaluates math expressions for tabletop games over
//! IRC. Stateless — a command parses an expression, rolls, and replies. ROLL/
//! CALC give the result (ROLL rounds to a whole number, CALC keeps decimals);
//! the EX variants also show each die. `N~expr` repeats a roll N times.
//!
//! `lib.rs` holds the dispatcher; the command lives in roll.rs and the
//! expression evaluator in expr.rs.

use echo_api::{HelpEntry, NetView, Sender, Service, ServiceCtx, Store};

#[path = "expr.rs"]
mod expr;
#[path = "roll.rs"]
mod roll;

const BLURB: &str = "DiceServ rolls dice and evaluates maths for tabletop games. Dice: \x022d6\x02, \x02d20\x02, \x02d%\x02. Also + - * / ^ %, parentheses, functions (sqrt, floor, min, ...), \x02pi\x02/\x02e\x02, and \x023~2d6\x02 to repeat.";

const TOPICS: &[HelpEntry] = &[
    HelpEntry { cmd: "ROLL", summary: "roll dice, whole-number result", detail: "Syntax: \x02ROLL <expr>\x02\nEvaluates a dice/math expression and rounds to a whole number, e.g. ROLL 2d6+3." },
    HelpEntry { cmd: "CALC", summary: "evaluate, keeping decimals", detail: "Syntax: \x02CALC <expr>\x02\nEvaluates an expression and keeps the decimals." },
    HelpEntry { cmd: "EXROLL", summary: "ROLL and show each die", detail: "Syntax: \x02EXROLL <expr>\x02\nLike ROLL, and also shows each individual die rolled." },
    HelpEntry { cmd: "EXCALC", summary: "CALC and show each die", detail: "Syntax: \x02EXCALC <expr>\x02\nLike CALC, and also shows each individual die rolled." },
];

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
            Some("ROLL") => roll::handle(me, from, &args[1..], ctx, false, true),
            Some("EXROLL") => roll::handle(me, from, &args[1..], ctx, true, true),
            Some("CALC") => roll::handle(me, from, &args[1..], ctx, false, false),
            Some("EXCALC") => roll::handle(me, from, &args[1..], ctx, true, false),
            Some("HELP") | None => echo_api::help(me, from, ctx, BLURB, TOPICS, args.get(1).copied()),
            Some(other) => ctx.notice(me, from.uid, format!("I don't know \x02{other}\x02. Try \x02ROLL\x02, \x02CALC\x02, or \x02HELP\x02.")),
        }
    }
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
