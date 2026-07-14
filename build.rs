fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Server only: the Rust side never needs to dial itself as a gRPC client.
    // Django (or any other consumer) generates its own stub from proto/echo.proto.
    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .compile_protos(&["proto/echo.proto"], &["proto"])?;
    println!("cargo:rerun-if-changed=proto/echo.proto");
    Ok(())
}
