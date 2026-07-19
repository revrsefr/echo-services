use echo_api::{t, Sender, ServiceCtx};

use super::expr;

// `N~expr` may repeat a roll at most this many times.
const MAX_REPEATS: u32 = 25;

// ROLL/EXROLL/CALC/EXCALC <expr>: evaluate a dice/math expression and reply.
// `round_result` gives a whole number (ROLL); `extended` also shows each die.
pub fn handle(me: &str, from: &Sender, rest: &[&str], ctx: &mut ServiceCtx, extended: bool, round_result: bool) {
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
                ctx.notice(me, from.uid, t!(ctx, "The repeat count before \x02~\x02 must be a number from 1 to {max}.", max = MAX_REPEATS));
                return;
            }
        },
        None => (1, input),
    };

    let mut rng = rand::thread_rng();
    let mut spent = 0u64; // dice rolled across the whole repeat batch
    for i in 0..times {
        match expr::evaluate(body, &mut rng) {
            Ok(ev) => {
                spent += ev.total;
                let result = format_value(ev.value, round_result);
                let prefix = if times > 1 { format!("[{}/{}] ", i + 1, times) } else { String::new() };
                let detail = if extended && !ev.rolls.is_empty() {
                    format!(" — {}", ev.rolls.iter().map(render_roll).collect::<Vec<_>>().join(", "))
                } else {
                    String::new()
                };
                ctx.notice(me, from.uid, format!("{prefix}\x02{body}\x02 = \x02{result}\x02{detail}"));
                // Bound total work across the whole `N~` batch, not per-evaluate, so
                // `25~99999d1+…` can't multiply the per-roll cap into tens of millions.
                if spent >= expr::MAX_TOTAL {
                    if i + 1 < times {
                        ctx.notice(me, from.uid, "That's a lot of dice — stopping the repeats here.");
                    }
                    break;
                }
            }
            Err(why) => {
                ctx.notice(me, from.uid, t!(ctx, "I couldn't roll \x02{body}\x02: {why}.", body = body, why = why));
                return; // the whole batch shares the expression, so it'll fail the same way
            }
        }
    }
}

// "2d6: 4+5=9" for the extended output.
fn render_roll(r: &expr::Roll) -> String {
    if r.values.len() == 1 {
        return format!("{}: {}", r.spec, r.total);
    }
    // For a huge roll the kept face list is capped, so the addends wouldn't sum to
    // the true total — show the total alone rather than a listing that doesn't add up.
    if r.values.iter().copied().sum::<u64>() != r.total {
        return format!("{}: {} (first {} dice)", r.spec, r.total, r.values.len());
    }
    let each = r.values.iter().map(u64::to_string).collect::<Vec<_>>().join("+");
    format!("{}: {}={}", r.spec, each, r.total)
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
