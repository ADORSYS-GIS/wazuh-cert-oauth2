use crate::ports::utils::parse_key_val;
use clap::Parser;
use std::path::PathBuf;

/// Which IdP to use for user lookups, event parsing, and revocation.
#[derive(Debug, Clone, PartialEq, clap::ValueEnum, Default)]
pub enum IdpType {
    #[default]
    Keycloak,
    Ferriskey,
    Google,
}

/// Which inbound webhook auth strategy to use.
#[derive(Debug, Clone, PartialEq, clap::ValueEnum, Default)]
pub enum WebhookAuthType {
    #[default]
    Default,
    Google,
}

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

    // --- IdP selection ---
    #[arg(long, env = "IDP_TYPE", default_value = "keycloak")]
    pub idp_type: IdpType,

    /// New canonical env var for the IdP admin base URL.
    #[arg(long, env = "IDP_ADMIN_BASE_URL")]
    pub idp_admin_base_url: Option<String>,

    #[arg(long, env = "IDP_REVOKE_REASON")]
    pub idp_revoke_reason: Option<String>,

    /// Google Workspace Customer ID.
    #[arg(long, env = "GOOGLE_CUSTOMER")]
    pub google_customer: Option<String>,

    /// Google Workspace domain (e.g. "mydomain.com").
    /// Use this when your watch channel is registered per-domain.
    /// Either GOOGLE_DOMAIN or GOOGLE_CUSTOMER must be set when IDP_TYPE=google.
    #[arg(long, env = "GOOGLE_DOMAIN")]
    pub google_domain: Option<String>,

    // --- Auth adapter selection ---
    #[arg(long, env = "WEBHOOK_AUTH_TYPE", default_value = "default")]
    pub webhook_auth_type: WebhookAuthType,

    // Universal inbound webhook auth
    #[arg(long, env = "WEBHOOK_BASIC_USER")]
    pub webhook_basic_user: Option<String>,
    #[arg(long, env = "WEBHOOK_BASIC_PASSWORD")]
    pub webhook_basic_password: Option<String>,
    #[arg(long, env = "WEBHOOK_API_KEY")]
    pub webhook_api_key: Option<String>,
    #[arg(long, env = "WEBHOOK_BEARER_TOKEN")]
    pub webhook_bearer_token: Option<String>,

    /// Extra headers the inbound webhook must present, as a comma-separated
    /// list of `KEY=VALUE` pairs (e.g. `X-Hub-Sig=abc,X-My-Header=val`).
    #[arg(
        long,
        env = "WEBHOOK_CUSTOM_HEADERS",
        value_delimiter = ',',
        value_parser = parse_key_val,
        num_args = 0..
    )]
    pub webhook_custom_headers: Vec<(String, String)>,

    // Google-specific (only read when WEBHOOK_AUTH_TYPE=google)
    #[arg(long, env = "GOOGLE_CHANNEL_ID")]
    pub google_channel_id: Option<String>,
    #[arg(long, env = "GOOGLE_CHANNEL_TOKEN")]
    pub google_channel_token: Option<String>,

    // GitHub Ticket Creation (for REGISTER/USER_CREATE events)
    #[arg(long, env = "GITHUB_TOKEN")]
    pub github_token: Option<String>,

    #[arg(long, env = "GITHUB_REPO_OWNER")]
    pub github_repo_owner: Option<String>,

    #[arg(long, env = "GITHUB_REPO_NAME")]
    pub github_repo_name: Option<String>,

    // Wazuh Manager API — eviction pipeline
    #[arg(long, env = "WAZUH_MANAGER_URL")]
    pub wazuh_manager_url: Option<String>,
    #[arg(long, env = "WAZUH_API_USER")]
    pub wazuh_api_user: Option<String>,
    #[arg(long, env = "WAZUH_API_PASSWORD")]
    pub wazuh_api_password: Option<String>,
    #[arg(long, env = "WAZUH_API_TOKEN")]
    pub wazuh_api_token: Option<String>,
    #[arg(long, env = "WAZUH_AR_COMMAND_UNIX", default_value = "delete-cert.sh")]
    pub wazuh_ar_command_unix: String,
    #[arg(
        long,
        env = "WAZUH_AR_COMMAND_WINDOWS",
        default_value = "delete-cert.ps1"
    )]
    pub wazuh_ar_command_windows: String,
    #[arg(long, env = "WAZUH_EVICTION_GRACE_SECONDS", default_value_t = 30)]
    pub wazuh_eviction_grace_seconds: u64,
    #[arg(long, env = "WAZUH_AR_SPOOL_TTL_SECONDS", default_value_t = 86400)]
    pub wazuh_ar_spool_ttl_seconds: u64,
}

impl Opt {
    pub fn validate(&self) -> Result<(), String> {
        match self.idp_type {
            IdpType::Keycloak => {
                if self.idp_admin_base_url.is_none() {
                    return Err("IDP_TYPE=keycloak requires IDP_ADMIN_BASE_URL to be set".into());
                }
            }
            IdpType::Ferriskey => {
                if self.idp_admin_base_url.is_none() {
                    return Err("IDP_TYPE=ferriskey requires IDP_ADMIN_BASE_URL to be set".into());
                }
            }
            IdpType::Google => {
                if self.google_domain.is_none() && self.google_customer.is_none() {
                    return Err(
                        "IDP_TYPE=google requires either GOOGLE_DOMAIN or GOOGLE_CUSTOMER to be set".into(),
                    );
                }

                if self.google_customer.is_some() && self.google_domain.is_some() {
                    return Err(
                        "IDP_TYPE=google requires either GOOGLE_DOMAIN or GOOGLE_CUSTOMER to be set".into(),
                    );
                }
            }
        }

        match self.webhook_auth_type {
            WebhookAuthType::Google => {
                if self.google_channel_id.as_deref().unwrap_or("").is_empty() {
                    return Err(
                        "WEBHOOK_AUTH_TYPE=google requires GOOGLE_CHANNEL_ID to be set".into(),
                    );
                }
                if self
                    .google_channel_token
                    .as_deref()
                    .unwrap_or("")
                    .is_empty()
                {
                    return Err(
                        "WEBHOOK_AUTH_TYPE=google requires GOOGLE_CHANNEL_TOKEN to be set".into(),
                    );
                }
            }
            WebhookAuthType::Default => {}
        }

        Ok(())
    }
}
