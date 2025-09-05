#[macro_use]
extern crate rocket;

use anyhow::*;
use clap::Parser;
use env_logger::{Builder, Env};
use log::{error, info};
use mimalloc::MiMalloc;
use std::path::PathBuf;
use std::time::Duration;
use wazuh_cert_oauth2_model::services::http_client::HttpClient;

mod handlers;
mod models;
mod state;

use crate::handlers::health::health;
use crate::handlers::webhook::send_webhook;
use crate::state::{ProxyState, spawn_spool_processor};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "wazuh-cert-oauth2-webhook",
    about = "Webhook proxy that forwards revocations with retry and failsafe"
)]
struct Opt {
    #[arg(long, env = "SERVER_BASE_URL")]
    server_base_url: String,

    #[arg(long, env = "SPOOL_DIR", default_value = "/data/spool")]
    spool_dir: PathBuf,

    #[arg(long, env = "RETRY_ATTEMPTS", default_value_t = 5)]
    retry_attempts: u32,

    #[arg(long, env = "RETRY_BASE_MS", default_value_t = 500)]
    retry_base_ms: u64,

    #[arg(long, env = "RETRY_MAX_MS", default_value_t = 8000)]
    retry_max_ms: u64,

    #[arg(long, env = "SPOOL_INTERVAL_SECS", default_value_t = 10)]
    spool_interval_secs: u64,

    // Optional direct bearer token (if you already have a valid OIDC token)
    #[arg(long, env = "PROXY_BEARER_TOKEN")]
    proxy_bearer_token: Option<String>,

    // OAuth2 (client credentials) for fetching a token to reach the server
    // If set, discovery is used to find the token endpoint.
    #[arg(long, env = "OAUTH_ISSUER")]
    oauth_issuer: Option<String>,

    #[arg(long, env = "OAUTH_CLIENT_ID")]
    oauth_client_id: Option<String>,

    #[arg(long, env = "OAUTH_CLIENT_SECRET")]
    oauth_client_secret: Option<String>,

    // Optional extra params
    #[arg(long, env = "OAUTH_SCOPE")]
    oauth_scope: Option<String>,

    #[arg(long, env = "OAUTH_AUDIENCE")]
    oauth_audience: Option<String>,

    // Keycloak mapping config
    #[arg(
        long,
        env = "KEYCLOAK_REVOKE_EVENT_TYPES",
        default_value = "USER_DISABLED,DELETE_USER,USER_DELETED"
    )]
    keycloak_revoke_event_types: String,

    #[arg(long, env = "KEYCLOAK_REVOKE_REASON", default_value = "keycloak-event")]
    keycloak_revoke_reason: String,

    // Incoming webhook auth (any that are set will be accepted)
    #[arg(long, env = "WEBHOOK_BASIC_USER")]
    webhook_basic_user: Option<String>,
    #[arg(long, env = "WEBHOOK_BASIC_PASSWORD")]
    webhook_basic_password: Option<String>,
    #[arg(long, env = "WEBHOOK_API_KEY")]
    webhook_api_key: Option<String>,
    #[arg(long, env = "WEBHOOK_BEARER_TOKEN")]
    webhook_bearer_token: Option<String>,
}

#[rocket::main]
async fn main() -> Result<()> {
    Builder::from_env(Env::default().default_filter_or("info")).init();
    info!("starting webhook");

    let Opt {
        server_base_url,
        spool_dir,
        retry_attempts,
        retry_base_ms,
        retry_max_ms,
        spool_interval_secs,
        proxy_bearer_token,
        oauth_issuer,
        oauth_client_id,
        oauth_client_secret,
        oauth_scope,
        oauth_audience,
        keycloak_revoke_event_types,
        keycloak_revoke_reason,
        webhook_basic_user,
        webhook_basic_password,
        webhook_api_key,
        webhook_bearer_token,
    } = Opt::parse();

    // Shared HTTP client
    let http_client = HttpClient::new_with_defaults()?;

    // Build state
    let state = ProxyState::new(
        server_base_url,
        spool_dir,
        http_client,
        retry_attempts,
        Duration::from_millis(retry_base_ms),
        Duration::from_millis(retry_max_ms),
        Duration::from_secs(spool_interval_secs),
        proxy_bearer_token,
        oauth_issuer,
        oauth_client_id,
        oauth_client_secret,
        oauth_scope,
        oauth_audience,
        keycloak_revoke_event_types,
        keycloak_revoke_reason,
        webhook_basic_user,
        webhook_basic_password,
        webhook_api_key,
        webhook_bearer_token,
    )?;

    // Spawn background spool processor
    let bg = state.clone();
    tokio::spawn(async move {
        if let Err(e) = spawn_spool_processor(bg).await {
            error!("spool processor exited: {}", e);
        }
    });

    rocket::build()
        .manage(state)
        .mount("/", routes![health])
        .mount("/api", routes![send_webhook])
        .launch()
        .await?;

    Ok(())
}
