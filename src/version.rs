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

/// The full multi-line banner for `echo --version`.
pub fn banner() -> String {
    let commit = if COMMIT_DATE.is_empty() {
        String::new()
    } else {
        format!(" ({COMMIT_DATE})")
    };
    format!(
        "echo \u{2014} federated IRC services\n  \
         version:  {VERSION}\n  \
         revision: {rev}{commit}\n  \
         built:    {built} ({profile})\n  \
         rustc:    {RUSTC}\n  \
         target:   {TARGET}",
        rev = revision(),
        built = built(),
        profile = profile(),
    )
}
