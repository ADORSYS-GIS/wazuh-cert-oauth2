use std::time::Duration;

use clap::Parser;
use log::{error, info};

#[derive(Parser, Debug)]
#[command(name = "healthcheck", version, about = "Simple HTTP healthcheck probe")]
struct Opt {
    #[arg(long, env = "HC_HOST", default_value = "127.0.0.1")]
    host: String,

    #[arg(long, env = "PORT", default_value_t = 8000)]
    port: u16,

    #[arg(long, env = "HEALTH_SCHEME", default_value = "http")]
    scheme: String,

    #[arg(long, env = "HEALTH_PATH", default_value = "/health")]
    path: String,

    #[arg(long, env = "HEALTH_TIMEOUT_MS", default_value_t = 3000)]
    timeout_ms: u64,
}

#[tokio::main]
async fn main() {
    // Initialize minimal logging if present
    let _ = env_logger::try_init();

    let opt = Opt::parse();

    let path = if opt.path.starts_with('/') {
        opt.path
    } else {
        format!("/{}", opt.path)
    };
    let url = format!("{}://{}:{}{}", opt.scheme, opt.host, opt.port, path);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(opt.timeout_ms))
        .build()
        .expect("failed to build client");

    match client.get(&url).send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                info!("healthcheck OK: {}", url);
                std::process::exit(0);
            } else {
                error!("healthcheck BAD_STATUS {}: {}", url, resp.status());
                std::process::exit(1);
            }
        }
        Err(err) => {
            error!("healthcheck ERROR {}: {}", url, err);
            std::process::exit(1);
        }
    }
}
