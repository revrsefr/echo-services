//! Static asset embedding for the web panel (CSS/JS). The pages themselves are
//! compile-time askama templates (see `src/panel/site/templates`, rendered by the
//! typed structs in `mod.rs`); this module only serves the theme's static files.

use include_dir::{include_dir, Dir};

static STATIC: Dir = include_dir!("$CARGO_MANIFEST_DIR/src/panel/site/static");

/// A static asset (css/js/…) by its path under `static/`, e.g. `css/theme.css`.
pub fn asset(path: &str) -> Option<(&'static [u8], &'static str)> {
    let f = STATIC.get_file(path)?;
    let ctype = match path.rsplit('.').next() {
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    };
    Some((f.contents(), ctype))
}

/// A relative timestamp in French ("il y a 3 min"), for panel display. Computed in
/// Rust so templates stay pure interpolation.
pub fn human_ago(then: u64, now: u64) -> String {
    let s = now.saturating_sub(then);
    if s < 60 {
        "à l'instant".into()
    } else if s < 3600 {
        format!("il y a {} min", s / 60)
    } else if s < 86400 {
        format!("il y a {} h", s / 3600)
    } else if s < 2_592_000 {
        format!("il y a {} j", s / 86400)
    } else {
        format!("il y a {} mois", s / 2_592_000)
    }
}

/// A forward relative delay in French ("dans 3 j"), for expiry display.
pub fn human_until(now: u64, then: u64) -> String {
    let s = then.saturating_sub(now);
    if s < 60 {
        "dans moins d'une minute".into()
    } else if s < 3600 {
        format!("dans {} min", s / 60)
    } else if s < 86400 {
        format!("dans {} h", s / 3600)
    } else if s < 2_592_000 {
        format!("dans {} j", s / 86400)
    } else {
        format!("dans {} mois", s / 2_592_000)
    }
}
