//! `echorpc` — a small control CLI that drives the running daemon over its gRPC
//! Admin service (`version`/`status`/`rehash`) and hands process lifecycle
//! (`start`/`stop`/`restart`) to systemd (you can't RPC a daemon that isn't
//! running). Invoked as `echorpc <cmd>` (a symlink to the echo binary) or
//! `echo ctl <cmd>`. An optional trailing arg overrides the config path
//! (default `config.toml` in the working directory).

use crate::grpc::pb;

pub async fn run(args: Vec<String>) -> anyhow::Result<()> {
    let verb = args.first().map(String::as_str).unwrap_or("");
    let config_path = args.get(1).cloned().unwrap_or_else(|| "config.toml".to_string());
    match verb {
        // Process lifecycle is systemd's job — a dead daemon has no gRPC to answer.
        "start" | "stop" | "restart" => {
            let status = std::process::Command::new("systemctl").arg(verb).arg("echo").status()?;
            std::process::exit(status.code().unwrap_or(1));
        }
        "version" | "status" => version(&config_path).await,
        "rehash" => rehash(&config_path).await,
        "" | "help" | "-h" | "--help" => {
            print_usage();
            Ok(())
        }
        other => {
            eprintln!("echorpc: unknown command '{other}'\n");
            print_usage();
            std::process::exit(2);
        }
    }
}

async fn connect(config_path: &str) -> anyhow::Result<(pb::admin_client::AdminClient<tonic::transport::Channel>, String)> {
    let cfg = crate::config::Config::load(config_path)?;
    let grpc = cfg
        .grpc
        .ok_or_else(|| anyhow::anyhow!("[grpc] is not configured in {config_path}; the control API needs it"))?;
    let scheme = if grpc.tls.is_some() { "https" } else { "http" };
    let endpoint = format!("{scheme}://{}", grpc.bind);
    let client = pb::admin_client::AdminClient::connect(endpoint)
        .await
        .map_err(|e| anyhow::anyhow!("cannot reach echo at {} ({e}); is the daemon running?", grpc.bind))?;
    Ok((client, grpc.token))
}

// Every Admin RPC carries the same bearer token the daemon's other gRPC clients use.
fn authed(token: &str) -> tonic::Request<pb::AdminRequest> {
    let mut req = tonic::Request::new(pb::AdminRequest {});
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().expect("valid header value"));
    req
}

async fn version(config_path: &str) -> anyhow::Result<()> {
    let (mut client, token) = connect(config_path).await?;
    let v = client.version(authed(&token)).await?.into_inner();
    let rustc = v.rustc.strip_prefix("rustc ").unwrap_or(&v.rustc);
    let (status, uptime) = if v.linked {
        ("linked", humanize(v.uptime_secs))
    } else {
        ("starting (not linked to the uplink yet)", "—".to_string())
    };
    println!("echo {} ({})", v.version, v.revision);
    println!("  built    {}", v.built);
    println!("  rustc    {rustc}");
    println!("  status   {status}");
    println!("  uptime   {uptime}");
    Ok(())
}

async fn rehash(config_path: &str) -> anyhow::Result<()> {
    let (mut client, token) = connect(config_path).await?;
    let r = client.rehash(authed(&token)).await?.into_inner();
    println!("{} {}", if r.ok { "✓" } else { "✗" }, r.message);
    Ok(())
}

fn humanize(secs: u64) -> String {
    let (d, h, m) = (secs / 86400, (secs % 86400) / 3600, (secs % 3600) / 60);
    let mut out = Vec::new();
    if d > 0 {
        out.push(format!("{d}d"));
    }
    if h > 0 {
        out.push(format!("{h}h"));
    }
    if m > 0 || out.is_empty() {
        out.push(format!("{m}m"));
    }
    out.join(" ")
}

fn print_usage() {
    eprintln!(
        "usage: echorpc <command> [config.toml]\n\n\
         talks to the running daemon (gRPC):\n  \
         version, status   the running build, uptime, and uplink state\n  \
         rehash            reload config.toml live (no restart)\n\n\
         process lifecycle (systemctl):\n  \
         start, stop, restart\n"
    );
}
