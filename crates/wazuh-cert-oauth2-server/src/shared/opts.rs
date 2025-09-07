use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "wazuh-cert-oauth2-server",
    about = "OAuth2-backed certificate issuance server for Wazuh agents"
)]
pub struct Opt {
    #[arg(long, env = "OAUTH_ISSUER", short = 'i')]
    pub oauth_issuer: String,

    #[arg(long, env = "KC_AUDIENCES")]
    pub kc_audiences: Option<String>,

    #[arg(long, env = "ROOT_CA_PATH", required = true, short = 'c')]
    pub root_ca_path: String,

    #[arg(long, env = "ROOT_CA_KEY_PATH", required = true, short = 'k')]
    pub root_ca_key_path: String,

    #[arg(long, env = "DISCOVERY_TTL_SECS", default_value_t = 3600)]
    pub discovery_ttl_secs: u64,

    #[arg(long, env = "JWKS_TTL_SECS", default_value_t = 300)]
    pub jwks_ttl_secs: u64,

    #[arg(long, env = "CA_CACHE_TTL_SECS", default_value_t = 300)]
    pub ca_cache_ttl_secs: u64,

    #[arg(long, env = "CRL_DIST_URL")]
    pub crl_dist_url: Option<String>,

    #[arg(long, env = "CRL_PATH", default_value = "/data/issuing.crl")]
    pub crl_path: String,

    #[arg(long, env = "LEDGER_PATH", default_value = "/data/ledger.csv")]
    pub ledger_path: String,
}
