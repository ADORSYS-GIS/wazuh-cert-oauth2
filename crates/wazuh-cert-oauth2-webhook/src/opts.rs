use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "wazuh-cert-oauth2-webhook",
    about = "Webhook proxy that forwards revocations with retry and failsafe"
)]
pub struct Opt {
    #[arg(long, env = "SERVER_BASE_URL")]
    pub server_base_url: String,

    #[arg(long, env = "SPOOL_DIR", default_value = "/data/spool")]
    pub spool_dir: PathBuf,

    #[arg(long, env = "RETRY_ATTEMPTS", default_value_t = 5)]
    pub retry_attempts: u32,

    #[arg(long, env = "RETRY_BASE_MS", default_value_t = 500)]
    pub retry_base_ms: u64,

    #[arg(long, env = "RETRY_MAX_MS", default_value_t = 8000)]
    pub retry_max_ms: u64,

    #[arg(long, env = "SPOOL_INTERVAL_SECS", default_value_t = 10)]
    pub spool_interval_secs: u64,

    // Optional direct bearer token (if you already have a valid OIDC token)
    #[arg(long, env = "PROXY_BEARER_TOKEN")]
    pub proxy_bearer_token: Option<String>,

    // OAuth2 (client credentials) for fetching a token to reach the server
    // If set, discovery is used to find the token endpoint.
    #[arg(long, env = "OAUTH_ISSUER")]
    pub oauth_issuer: Option<String>,

    #[arg(long, env = "OAUTH_CLIENT_ID")]
    pub oauth_client_id: Option<String>,

    #[arg(long, env = "OAUTH_CLIENT_SECRET")]
    pub oauth_client_secret: Option<String>,

    // Optional extra params
    #[arg(long, env = "OAUTH_SCOPE")]
    pub oauth_scope: Option<String>,

    #[arg(long, env = "OAUTH_AUDIENCE")]
    pub oauth_audience: Option<String>,

    // Reason string to attach to revocations created from webhook events
    #[arg(long, env = "KEYCLOAK_REVOKE_REASON", default_value = "Keycloak event")]
    pub keycloak_revoke_reason: String,

    // Incoming webhook auth (any that are set will be accepted)
    #[arg(long, env = "WEBHOOK_BASIC_USER")]
    pub webhook_basic_user: Option<String>,
    #[arg(long, env = "WEBHOOK_BASIC_PASSWORD")]
    pub webhook_basic_password: Option<String>,
    #[arg(long, env = "WEBHOOK_API_KEY")]
    pub webhook_api_key: Option<String>,
    #[arg(long, env = "WEBHOOK_BEARER_TOKEN")]
    pub webhook_bearer_token: Option<String>,
}
