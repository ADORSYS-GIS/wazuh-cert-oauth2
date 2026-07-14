use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "wazuh-cert-oauth2-webhook",
    version,
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

    // GitHub Ticket Creation (for REGISTER/USER_CREATE events)
    #[arg(long, env = "GITHUB_TOKEN")]
    pub github_token: Option<String>,

    #[arg(long, env = "GITHUB_REPO_OWNER")]
    pub github_repo_owner: Option<String>,

    #[arg(long, env = "GITHUB_REPO_NAME")]
    pub github_repo_name: Option<String>,
    #[arg(long, env = "KEYCLOAK_ADMIN_BASE_URL")]
    pub keycloak_admin_base_url: Option<String>,

    // Wazuh Manager API — eviction pipeline
    #[arg(long, env = "WAZUH_MANAGER_URL")]
    pub wazuh_manager_url: Option<String>,
    #[arg(long, env = "WAZUH_API_USER")]
    pub wazuh_api_user: Option<String>,
    #[arg(long, env = "WAZUH_API_PASSWORD")]
    pub wazuh_api_password: Option<String>,
    #[arg(long, env = "WAZUH_API_TOKEN")]
    pub wazuh_api_token: Option<String>,
    #[arg(long, env = "WAZUH_EVICTION_GRACE_SECONDS", default_value_t = 30)]
    pub wazuh_eviction_grace_seconds: u64,
    /// Enable TLS certificate verification for the Wazuh Manager API.
    /// Defaults to `true` for security. Set to `false` only for testing or
    /// when using self-signed certificates without a configured CA bundle.
    #[arg(long, env = "WAZUH_API_TLS_VERIFY", default_value_t = true)]
    pub wazuh_api_tls_verify: bool,
    /// Path to a PEM file containing additional CA certificates to trust
    /// for the Wazuh Manager API (e.g. for self-signed managers).
    #[arg(long, env = "WAZUH_API_CA_BUNDLE")]
    pub wazuh_api_ca_bundle: Option<std::path::PathBuf>,

    /// Maximum age (in seconds) an eviction request stays in the spool before
    /// being moved to the dead-letter directory. Defaults to 24h (86400).
    #[arg(long, env = "SPOOL_EVICT_TTL_SECS", default_value_t = 86_400)]
    pub spool_evict_ttl_secs: u64,

    /// Directory where expired eviction spool items are quarantined for
    /// operator inspection/replay.
    #[arg(long, env = "SPOOL_DEAD_LETTER_DIR")]
    pub spool_dead_letter_dir: Option<PathBuf>,
}
