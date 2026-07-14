use echo_api::{Sender, ServiceCtx, Store};

// TEMPLATE [<pattern>]: show the auto-vhost template, or (operators) set it.
// Use $account for the requester's sanitised account name, e.g.
// $account.users.example. Give no argument to show it, OFF to clear it.
pub fn handle(me: &str, from: &Sender, args: &[&str], ctx: &mut ServiceCtx, db: &mut dyn Store) {
    match args.get(1) {
        None => match db.vhost_template() {
            Some(t) => ctx.notice(me, from.uid, format!("Auto-vhost template: \x02{t}\x02. Users apply it with \x02DEFAULT\x02.")),
            None => ctx.notice(me, from.uid, "No auto-vhost template is set."),
        },
        Some(&arg) => {
            if !super::require_oper(me, from, ctx) {
                return;
            }
            if arg.eq_ignore_ascii_case("OFF") {
                let _ = db.set_vhost_template(None);
                ctx.notice(me, from.uid, "Auto-vhost template cleared.");
                return;
            }
            let template = args[1..].join(" ");
            if !template.contains("$account") || !super::valid_vhost(&template.replace("$account", "x")) {
                ctx.notice(me, from.uid, "The template must contain \x02$account\x02 and form a valid host, e.g. \x02$account.users.example\x02.");
                return;
            }
            match db.set_vhost_template(Some(template.clone())) {
                Ok(()) => ctx.notice(me, from.uid, format!("Auto-vhost template set to \x02{template}\x02.")),
                Err(_) => ctx.notice(me, from.uid, "Sorry, that didn't work. Please try again in a moment."),
            }
        }
    }
}
