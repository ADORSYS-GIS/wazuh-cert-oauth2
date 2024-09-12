use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "Wazuh Configurer", about = "Installs and configures Wazuh, YARA, and Snort")]
pub enum Opt {
    #[structopt(about = "Configure OAuth2 for Wazuh")]
    OAuth2 {
        #[structopt(long, default_value = "https://login.wazuh.adorsys.team/realms/adorsys")]
        issuer: String,

        #[structopt(long, short = "i", default_value = "adorsys-machine-client")]
        client_id: String,

        #[structopt(long, short = "s")]
        client_secret: Option<String>,

        #[structopt(
            long,
            short = "e",
            default_value = "https://cert.wazuh.adorsys.team/api/register-agent"
        )]
        endpoint: String,

        #[structopt(long, short = "c", default_value = "/var/ossec/etc/sslagent.cert")]
        cert_path: String,

        #[structopt(long, short = "k", default_value = "/var/ossec/etc/sslagent.key")]
        key_path: String,
    },
}
