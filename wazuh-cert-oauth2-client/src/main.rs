#[macro_use]
extern crate log;

use std::env::var;

use crate::services::get_token::get_token;
use crate::services::get_user_keys::fetch_user_keys;
use crate::services::save_to_file::save_keys;
use crate::services::set_name::set_name;
use crate::shared::cli::Opt;
use crate::shared::constants::*;
use crate::shared::path::{default_cert_path, default_key_path};
use anyhow::Result;
use env_logger::{Builder, Env};
use structopt::StructOpt;
use wazuh_cert_oauth2_model::models::claims::Claims;
use wazuh_cert_oauth2_model::models::document::DiscoveryDocument;
use wazuh_cert_oauth2_model::services::fetch_only::fetch_only;
use wazuh_cert_oauth2_model::services::jwks::validate_token;

mod services;
mod shared;


#[tokio::main]
async fn main() -> Result<()> {
    Builder::from_env(Env::default().default_filter_or("info")).init();

    info!("starting up");

    match Opt::from_args() {
        Opt::OAuth2 {
            issuer: default_issuer,
            audience: default_audiences,
            client_id: default_client_id,
            client_secret: default_client_secret,
            endpoint: default_endpoint,
        } => {
            let issuer = var(OAUTH2_ISSUER).unwrap_or(default_issuer);
            let client_id = var(OAUTH2_CLIENT_ID).unwrap_or(default_client_id);
            let client_secret = var(OAUTH2_CLIENT_SECRET).ok().or_else(|| default_client_secret);
            let endpoint = var(ENDPOINT).unwrap_or(default_endpoint);
            let cert_path = var(PUBLIC_KEY_FILE).unwrap_or_else(|_| default_cert_path());
            let key_path = var(PRIVATE_KEY_FILE).unwrap_or_else(|_| default_key_path());

            let kc_audiences = var("KC_AUDIENCES").unwrap_or(default_audiences);
            let kc_audiences = kc_audiences
                .split(",")
                .map(|s| s.to_string())
                .collect::<Vec<String>>();

            let document = fetch_only::<DiscoveryDocument>(&format!("{}/.well-known/openid-configuration", issuer)).await?;
            let jwks = fetch_only(&document.jwks_uri).await?;

            let token = get_token(&issuer, &client_id, client_secret).await?;
            match validate_token(&token, &jwks, &kc_audiences).await {
                Ok(Claims { name, .. }) => {
                    let user_key = fetch_user_keys(&endpoint, &token).await?;
                    save_keys(&cert_path, &key_path, &user_key).await?;
                    info!("Keys saved successfully!");

                    set_name(&name).await?;
                    info!("Name set successfully!");
                }
                Err(_) => {
                    error!("Unauthorized");
                }
            }
        }
    }

    Ok(())
}