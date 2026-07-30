use clap::Parser;

#[derive(Parser, Debug, Clone)]
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

    #[arg(long, env = "WAZUH_MANAGER_URL", required = true)]
    pub wazuh_manager_url: String,

    #[arg(long, env = "WAZUH_API_USER", required = true)]
    pub wazuh_api_user: String,

    #[arg(long, env = "WAZUH_API_PASSWORD", required = true)]
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

    #[arg(long, env = "KEYCLOAK_ADMIN_URL", required = true)]
    pub keycloak_admin_url: String,

    #[arg(long, env = "KEYCLOAK_REALM")]
    pub keycloak_realm: String,

    #[arg(long, env = "KEYCLOAK_AUTH_METHOD", default_value = "password")]
    pub keycloak_auth_method: KeycloakAuthMethod,

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

use std::{fmt::Display, str::FromStr};

#[derive(Debug, Clone)]
pub enum KeycloakAuthMethod {
    Password,
    ClientCredentials,
}

impl FromStr for KeycloakAuthMethod {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "password" => Ok(Self::Password),
            "client-credentials" => Ok(Self::ClientCredentials),
            _ => Err(format!(
                "invalid auth method '{s}'. Expected 'password' or 'client-credentials'"
            )),
        }
    }
}

impl Display for KeycloakAuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password => write!(f, "password"),
            Self::ClientCredentials => write!(f, "client-credentials"),
        }
    }
}
