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
        .build_client(false)
        .compile_protos(&["proto/echo.proto"], &["proto"])?;
    println!("cargo:rerun-if-changed=proto/echo.proto");
    Ok(())
}
