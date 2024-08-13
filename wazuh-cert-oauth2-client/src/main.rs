#[macro_use]
extern crate log;

use std::env::var;

use anyhow::Result;
use structopt::StructOpt;

use crate::cli::Opt;
use crate::services::get_token::get_token;
use crate::services::get_user_keys::fetch_user_keys;
use crate::services::save_to_file::save_keys;

mod errors;
mod cli;
mod services;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    info!("starting up");

    match Opt::from_args() {
        Opt::OAuth2 { issuer: default_issuer, client_id: default_client_id, client_secret: default_client_secret, endpoint: default_endpoint, cert_path: default_cert_path, key_path: default_key_path } => {
            let issuer = var("OAUTH2_ISSUER").unwrap_or(default_issuer);
            let client_id = var("OAUTH2_CLIENT_ID").unwrap_or(default_client_id);
            let endpoint = var("ENDPOINT").unwrap_or(default_endpoint);
            let cert_path = var("PUBLIC_KEY_FILE").unwrap_or_else(|_| default_cert_path);
            let key_path = var("PRIVATE_KEY_FILE").unwrap_or_else(|_| default_key_path);

            let token = get_token(&issuer, &client_id, None).await?;
            let user_key = fetch_user_keys(&endpoint, &token).await?;
            save_keys(&cert_path, &key_path, &user_key).await?;
            info!("Keys saved successfully!");
        }
    }

    Ok(())
}
