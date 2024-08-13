use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "Wazuh Configurer", about = "Installs and configures Wazuh, YARA, and Snort")]
pub enum Opt {
    #[structopt(about = "Configure OAuth2 for Wazuh")]
    OAuth2 {
        #[structopt(long, short = "i", default_value = "https://accounts.ssegning.com/realms/adorsys")]
        issuer: String,

        #[structopt(long, short = "c", default_value = "adorsys-machine-client")]
        client_id: String,

        #[structopt(long, short = "s")]
        client_secret: String,

        #[structopt(long, short = "e", default_value = "https://cert.wazuh.adorsys.team/api/register-agent")]
        endpoint: String,

        #[structopt(long, short = "u", default_value = "")]
        public_key_file: String,

        #[structopt(long, short = "r", default_value = "")]
        private_key_file: String,
    },
}
