//! HTML shell for the admin panel: one self-contained document per page (inline
//! CSS, no external assets), a sidebar when signed in, and the login layout when
//! not. Kept deliberately plain — server-rendered, no client build step.

use super::Oper;

// Minimal HTML escape for interpolated text.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn nav_item(href: &str, key: &str, active: &str, label: &str) -> String {
    let cls = if key == active { "nav-item active" } else { "nav-item" };
    format!("<a class=\"{cls}\" href=\"{href}\">{label}</a>")
}

pub fn shell(brand: &str, oper: Option<&Oper>, active: &str, body: &str) -> String {
    let chrome = match oper {
        Some(o) => {
            let nav = format!(
                "{}{}{}{}",
                nav_item("/", "", active, "Dashboard"),
                nav_item("/accounts", "accounts", active, "Accounts"),
                nav_item("/channels", "channels", active, "Channels"),
                nav_item("/network", "network", active, "Network"),
            );
            format!(
                "<div class=\"app\">\
                   <aside class=\"side\"><div class=\"brand\">{brand}</div><nav>{nav}</nav></aside>\
                   <div class=\"main\">\
                     <header class=\"top\"><div class=\"who\">{who}<span class=\"tier\">{tier}</span></div>\
                       <form method=\"post\" action=\"/logout\"><button class=\"logout\">Sign out</button></form></header>\
                     <div class=\"content\">{body}</div>\
                   </div>\
                 </div>",
                brand = esc(brand),
                nav = nav,
                who = esc(&o.account),
                tier = esc(o.privs.tier()),
                body = body,
            )
        }
        None => body.to_string(),
    };
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"robots\" content=\"noindex\"><title>{title}</title><style>{css}</style></head>\
         <body>{chrome}</body></html>",
        title = esc(brand),
        css = CSS,
        chrome = chrome,
    )
}

const CSS: &str = r#"
:root{--bg:#0f1220;--panel:#171a2b;--panel2:#1d2136;--line:#2a2f4a;--ink:#e7e9f3;--muted:#9aa0bf;--accent:#6d8bff;--accent2:#8a6dff;--ok:#3ecf8e;--warn:#ffb454;--bad:#ff6b6b;--radius:12px}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.app{display:grid;grid-template-columns:230px 1fr;min-height:100vh}
.side{background:var(--panel);border-right:1px solid var(--line);padding:20px 14px;position:sticky;top:0;height:100vh}
.brand{font-weight:700;font-size:18px;letter-spacing:.2px;padding:6px 10px 18px}
nav{display:flex;flex-direction:column;gap:2px}
.nav-item{color:var(--muted);padding:10px 12px;border-radius:10px;font-weight:500}
.nav-item:hover{background:var(--panel2);color:var(--ink);text-decoration:none}
.nav-item.active{background:linear-gradient(90deg,var(--accent),var(--accent2));color:#fff}
.main{display:flex;flex-direction:column;min-width:0}
.top{display:flex;justify-content:flex-end;align-items:center;gap:16px;padding:14px 28px;border-bottom:1px solid var(--line)}
.who{color:var(--muted);font-size:13px}.who .tier{margin-left:8px;color:var(--ink);background:var(--panel2);border:1px solid var(--line);padding:2px 8px;border-radius:20px}
.logout{background:transparent;color:var(--muted);border:1px solid var(--line);padding:7px 12px;border-radius:8px;cursor:pointer}
.logout:hover{color:var(--ink);border-color:var(--accent)}
.content{padding:28px;max-width:1100px;width:100%}
h1{font-size:22px;margin:0 0 20px}h2{font-size:15px;margin:0 0 12px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:20px;margin-bottom:20px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:16px;margin-bottom:20px}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:18px 20px}
.stat-v{font-size:28px;font-weight:700}.stat-l{color:var(--muted);font-size:13px;margin-top:4px}
table{width:100%;border-collapse:collapse}
table.kv td{padding:7px 0;border-bottom:1px solid var(--line)}table.kv td:first-child{color:var(--muted);width:130px}
table.list th{text-align:left;color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.4px;padding:0 12px 10px;border-bottom:1px solid var(--line)}
table.list td{padding:11px 12px;border-bottom:1px solid var(--line)}
table.list tbody tr:hover{background:var(--panel2)}
.tag{display:inline-block;font-size:11px;padding:2px 8px;border-radius:20px;margin-left:6px;font-weight:600}
.tag.warn{background:rgba(255,180,84,.15);color:var(--warn)}.tag.bad{background:rgba(255,107,107,.15);color:var(--bad)}.tag.op{background:rgba(109,139,255,.15);color:var(--accent)}
.ok{color:var(--ok)}.warn{color:var(--warn)}.muted{color:var(--muted);font-size:13px}
.search{display:flex;gap:8px;margin-bottom:16px}
.search input{flex:1;max-width:340px}
input{background:var(--panel2);border:1px solid var(--line);color:var(--ink);padding:10px 12px;border-radius:8px;font:inherit}
input:focus{outline:none;border-color:var(--accent)}
button{background:linear-gradient(90deg,var(--accent),var(--accent2));color:#fff;border:0;padding:10px 16px;border-radius:8px;font:inherit;font-weight:600;cursor:pointer}
.login-wrap{min-height:100vh;display:grid;place-items:center;padding:24px}
.login{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:36px;width:340px}
.login h1{font-size:24px;margin:0}.login .sub{color:var(--muted);margin:4px 0 24px}
.login form{display:flex;flex-direction:column;gap:14px}
.login label{display:flex;flex-direction:column;gap:6px;font-size:13px;color:var(--muted)}
.login button{margin-top:6px;padding:12px}
.login .hint{color:var(--muted);font-size:12px;margin:18px 0 0;text-align:center}
.alert{background:rgba(255,107,107,.12);color:var(--bad);border:1px solid rgba(255,107,107,.3);padding:10px 12px;border-radius:8px;margin-bottom:16px;font-size:13px}
"#;
