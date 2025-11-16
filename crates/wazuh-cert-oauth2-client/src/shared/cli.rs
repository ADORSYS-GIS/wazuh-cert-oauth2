use crate::shared::path::{default_cert_path, default_key_path, default_server_ca_cert_path};
use clap::ArgAction;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    version,
    name = "Wazuh Cert Auth CLI",
    about = "Wazuh Certificate Authority",
    long_about = "Installs and configures Wazuh Certificate Authority"
)]
pub enum Opt {
    #[command(about = "Configure OAuth2 for Wazuh")]
    OAuth2 {
        #[arg(
            env,
            long,
            default_value = "https://login.wazuh.adorsys.team/realms/adorsys"
        )]
        issuer: String,

        #[arg(env, long, short = 'a', default_value = "account")]
        audience: String,

        #[arg(env, long, short = 'i', default_value = "adorsys-machine-client")]
        client_id: String,

        #[arg(env, long, short = 's')]
        client_secret: Option<String>,

        #[arg(
            env,
            long,
            short = 'e',
            default_value = "https://cert.wazuh.adorsys.team/api/register-agent"
        )]
        endpoint: String,

        #[arg(env, long, default_value_t = false, action = ArgAction::Set)]
        is_service_account: bool,

        #[arg(env, long, default_value_t = default_server_ca_cert_path(), short = 'r')]
        ca_cert_path: String,

        #[arg(env, long, default_value_t = default_cert_path(), short = 'c')]
        cert_path: String,

        #[arg(env, long, default_value_t = default_key_path(), short = 'k')]
        key_path: String,

        #[arg(env, long, default_value_t = true, action = ArgAction::Set, default_missing_value = "true", num_args = 0..=1)]
        agent_control: bool,
    },
}
