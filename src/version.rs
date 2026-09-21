//! Build/version metadata, captured at compile time by `build.rs` and formatted
//! for `echo --version`, the startup log, and the CTCP VERSION reply.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const GIT_HASH: &str = env!("ECHO_GIT_HASH");
pub const GIT_DIRTY: &str = env!("ECHO_GIT_DIRTY"); // "-dirty" or ""
pub const COMMIT_DATE: &str = env!("ECHO_COMMIT_DATE");
pub const RUSTC: &str = env!("ECHO_RUSTC");
pub const TARGET: &str = env!("ECHO_TARGET");
const BUILD_EPOCH: &str = env!("ECHO_BUILD_EPOCH");

fn profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

/// The build time as "YYYY-MM-DD HH:MM:SS UTC".
pub fn built() -> String {
    echo_api::human_time(BUILD_EPOCH.parse().unwrap_or(0))
}

/// `git a1b2c3d4e5f6` (or `…-dirty`), the revision alone.
pub fn revision() -> String {
    format!("{GIT_HASH}{GIT_DIRTY}")
}

/// One compact line — for the CTCP VERSION reply and the startup log.
/// `echo 0.0.1 (a1b2c3d4e5f6)`.
pub fn short() -> String {
    format!("echo {VERSION} ({})", revision())
}

// ASCII wordmark (figlet "standard", "echo").
const LOGO: [&str; 5] = [
    r"            _           ",
    r"   ___  ___| |__   ___  ",
    r"  / _ \/ __| '_ \ / _ \ ",
    r" |  __/ (__| | | | (_) |",
    r"  \___|\___|_| |_|\___/ ",
];

/// The full banner for `echo --version` / an interactive startup. `color` emits
/// ANSI styling (only when writing to a terminal).
pub fn banner(color: bool) -> String {
    let (logo, name, dim, reset) = if color {
        ("\x1b[38;5;44m", "\x1b[1;38;5;51m", "\x1b[2m", "\x1b[0m")
    } else {
        ("", "", "", "")
    };
    #[allow(clippy::const_is_empty)] // ECHO_COMMIT_DATE can be empty in a non-git build
    let commit = if COMMIT_DATE.is_empty() {
        String::new()
    } else {
        format!("  {dim}({COMMIT_DATE}){reset}")
    };
    // Identity text aligned against the middle rows of the logo.
    let side = [
        String::new(),
        format!("{name}echo{reset} {dim}services{reset}"),
        format!("{dim}federated IRC services{reset}"),
        String::new(),
        String::new(),
    ];
    let mut out = String::from("\n");
    for i in 0..LOGO.len() {
        out.push_str(&format!("  {logo}{:<24}{reset}   {}\n", LOGO[i], side[i]));
    }
    out.push('\n');
    let mut row = |label: &str, value: String| {
        out.push_str(&format!("  {dim}{label:<9}{reset}{value}\n"));
    };
    row("version", VERSION.to_string());
    row("revision", format!("{}{commit}", revision()));
    row("built", format!("{} {dim}·{reset} {}", built(), profile()));
    row("rustc", RUSTC.strip_prefix("rustc ").unwrap_or(RUSTC).to_string());
    row("target", TARGET.to_string());
    out
}
