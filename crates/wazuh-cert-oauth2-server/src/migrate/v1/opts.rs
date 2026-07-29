use clap::Parser;

#[derive(Parser, Debug)]
#[command(about = "Backfill wazuh_agent_name for existing ledger entries")]
pub struct MigrateOpt {
    #[arg(long, env = "INPUT_LEDGER_PATH", default_value = "/data/ledger.csv")]
    pub input: String,

    #[arg(
        long,
        env = "OUTPUT_LEDGER_PATH",
        default_value = "ledger-migrated.csv"
    )]
    pub output: String,

    #[arg(long, env = "UNRESOLVED_PATH", default_value = "unresolved.csv")]
    pub unresolved: String,

    #[arg(long, env = "REPORT_PATH", default_value = "migration-report.txt")]
    pub report: String,

    #[arg(long, env = "WAZUH_MANAGER_URL")]
    pub wazuh_manager_url: String,

    #[arg(long, env = "WAZUH_API_USER")]
    pub wazuh_api_user: String,

    #[arg(long, env = "WAZUH_API_PASSWORD")]
    pub wazuh_api_password: String,

    /// Enable TLS certificate verification for the Wazuh Manager API.
    /// Defaults to `true` for security. Set to `false` only for testing
    /// or when using self-signed certificates without a configured CA bundle.
    #[arg(long, env = "WAZUH_TLS_VERIFY", default_value_t = true)]
    pub wazuh_tls_verify: bool,

    /// Path to a PEM file containing additional CA certificates to trust
    /// for the Wazuh Manager API (e.g. for self-signed managers).
    #[arg(long, env = "WAZUH_CA_BUNDLE")]
    pub wazuh_ca_bundle: Option<std::path::PathBuf>,

    #[arg(long, env = "KEYCLOAK_ADMIN_URL")]
    pub keycloak_admin_url: String,

    #[arg(long, env = "KEYCLOAK_REALM")]
    pub keycloak_realm: String,

    #[arg(long, env = "KEYCLOAK_AUTH_METHOD", default_value = "password")]
    pub keycloak_auth_method: String,

    #[arg(long, env = "KEYCLOAK_ADMIN_USER")]
    pub keycloak_admin_user: Option<String>,

    #[arg(long, env = "KEYCLOAK_ADMIN_PASSWORD")]
    pub keycloak_admin_password: Option<String>,

    #[arg(long, env = "KEYCLOAK_CLIENT_ID")]
    pub keycloak_client_id: Option<String>,

    #[arg(long, env = "KEYCLOAK_CLIENT_SECRET")]
    pub keycloak_client_secret: Option<String>,

    /// Enable TLS certificate verification for the Keycloak Admin API.
    /// Defaults to `true` for security. Set to `false` only for testing
    /// or when using self-signed certificates without a configured CA bundle.
    #[arg(long, env = "KEYCLOAK_TLS_VERIFY", default_value_t = true)]
    pub keycloak_tls_verify: bool,

    /// Path to a PEM file containing additional CA certificates to trust
    /// for the Keycloak Admin API (e.g. for self-signed Keycloak servers).
    #[arg(long, env = "KEYCLOAK_CA_BUNDLE")]
    pub keycloak_ca_bundle: Option<std::path::PathBuf>,
}
