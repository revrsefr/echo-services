fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use a vendored protoc, so `cargo build` needs no system protobuf compiler
    // (a fresh clone, CI, and the deploy box all build out of the box). Respect
    // an explicit PROTOC if one is already set.
    if std::env::var_os("PROTOC").is_none() {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);
    }
    // Server only: the Rust side never needs to dial itself as a gRPC client.
    // Django (or any other consumer) generates its own stub from proto/echo.proto.
    tonic_build::configure()
        .build_server(true)
        // The `echorpc` control CLI (in this same binary) dials the Admin service,
        // so we need the client stubs too. Django generates its own from the proto.
        .build_client(true)
        .compile_protos(&["proto/echo.proto"], &["proto"])?;
    println!("cargo:rerun-if-changed=proto/echo.proto");
    emit_build_info();
    Ok(())
}

// Capture the git revision and build metadata at compile time and expose them as
// `env!()`-readable vars, so the binary can print a real version banner (its own
// commit hash, build date, toolchain). Degrades gracefully when git is absent
// (a tarball build) — the fields just read "unknown"/empty.
fn emit_build_info() {
    use std::process::Command;
    let git = |args: &[&str]| {
        Command::new("git")
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
    };
    let hash = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let dirty = git(&["status", "--porcelain"]).map(|s| !s.is_empty()).unwrap_or(false);
    let commit_date = git(&["log", "-1", "--format=%cd", "--date=short"]).unwrap_or_default();

    // Build time (UTC seconds), honouring SOURCE_DATE_EPOCH for reproducible builds.
    let epoch = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        });
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let rustc_ver = Command::new(rustc)
        .arg("--version")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into());

    println!("cargo:rustc-env=ECHO_GIT_HASH={hash}");
    println!("cargo:rustc-env=ECHO_GIT_DIRTY={}", if dirty { "-dirty" } else { "" });
    println!("cargo:rustc-env=ECHO_COMMIT_DATE={commit_date}");
    println!("cargo:rustc-env=ECHO_BUILD_EPOCH={epoch}");
    println!("cargo:rustc-env=ECHO_RUSTC={rustc_ver}");
    println!("cargo:rustc-env=ECHO_TARGET={}", std::env::var("TARGET").unwrap_or_default());

    // Re-run (refresh the hash) when the checked-out commit moves.
    println!("cargo:rerun-if-changed=.git/HEAD");
    if let Ok(head) = std::fs::read_to_string(".git/HEAD") {
        if let Some(reference) = head.strip_prefix("ref: ").map(str::trim) {
            println!("cargo:rerun-if-changed=.git/{reference}");
        }
    }
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
}
