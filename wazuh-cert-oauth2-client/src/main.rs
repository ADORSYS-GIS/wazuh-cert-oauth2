#[macro_use]
extern crate log;

use std::env::var;

use crate::services::get_token::{get_token, GetTokenParams};
use crate::services::get_user_keys::fetch_user_keys;
use crate::services::restart_agent::restart_agent;
use crate::services::save_to_file::save_keys;
use crate::services::set_name::set_name;
use crate::services::stop_agent::stop_agent;
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
pub mod shared;

#[tokio::main]
async fn main() {
    Builder::from_env(Env::default().default_filter_or("info")).init();

    info!("starting up");

    match app().await {
        Ok(_) => {
            info!("Done!");
        }
        Err(e) => {
            error!("An error occurred during execution: {}", e);
        }
    }
}

async fn app() -> Result<()> {
    match Opt::from_args() {
        Opt::OAuth2 {
            issuer: default_issuer,
            audience: default_audiences,
            client_id: default_client_id,
            client_secret: default_client_secret,
            endpoint: default_endpoint,
            is_service_account: default_is_service_account,
        } => {
            let issuer = var(OAUTH2_ISSUER).unwrap_or(default_issuer);
            let client_id = var(OAUTH2_CLIENT_ID).unwrap_or(default_client_id);
            let client_secret = var(OAUTH2_CLIENT_SECRET)
                .ok()
                .or_else(|| default_client_secret);
            let endpoint = var(ENDPOINT).unwrap_or(default_endpoint);
            let cert_path = var(PUBLIC_KEY_FILE).unwrap_or_else(|_| default_cert_path());
            let key_path = var(PRIVATE_KEY_FILE).unwrap_or_else(|_| default_key_path());
            let is_service_account = var(IS_SERVICE_ACCOUNT)
                .map_or_else(|_| default_is_service_account == "true", |_| false);

            let kc_audiences = var("KC_AUDIENCES").unwrap_or(default_audiences);
            let kc_audiences = kc_audiences
                .split(",")
                .map(|s| s.to_string())
                .collect::<Vec<String>>();

            let document = fetch_only::<DiscoveryDocument>(&format!(
                "{}/.well-known/openid-configuration",
                issuer
            ))
            .await?;

            debug!("Stopping agent");
            stop_agent().await?;

            debug!("Getting JWKS");
            let jwks = fetch_only(&document.jwks_uri).await?;

            debug!("Getting token");
            let token = get_token(GetTokenParams {
                document,
                client_id,
                client_secret,
                is_service_account,
            })
            .await?;

            debug!("Validating token & getting the name claim");
            let name = validate_token(&token, &jwks, &kc_audiences)
                .await
                .map(|Claims { name, .. }| name)?;

            debug!("Fetching user keys");
            let user_key = fetch_user_keys(&endpoint, &token).await?;

            debug!("Saving keys");
            save_keys(&cert_path, &key_path, &user_key).await?;

            debug!("Setting name");
            set_name(&name).await?;

            debug!("Restarting agent");
            restart_agent().await?;

            info!("Name set successfully!");

            Ok(())
        }
    }
}
