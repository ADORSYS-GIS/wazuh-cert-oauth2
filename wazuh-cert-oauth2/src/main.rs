#[macro_use]
extern crate log;

#[macro_use]
extern crate rocket;

use std::env::var;

use anyhow::*;
use tokio::sync::RwLock;

use wazuh_cert_oauth2_model::models::document::DiscoveryDocument;
use wazuh_cert_oauth2_model::services::fetch_only::fetch_only;

use crate::handlers::health::health;
use crate::handlers::register_agent::register_agent;
use crate::models::jwks_state::JwksState;

mod errors;
mod handlers;
mod models;
mod shared;

#[rocket::main]
async fn main() -> Result<()> {
    env_logger::init();

    info!("starting up");

    let binding = var("KC_AUDIENCES").or_else(|_| Ok("account".to_string()))?;
    let kc_audiences = binding
        .split(",")
        .map(|s| s.to_string());


    let oauth_issuer = var("OAUTH_ISSUER")?;
    let document = fetch_only::<DiscoveryDocument>(&format!("{}/.well-known/openid-configuration", oauth_issuer)).await?;

    info!("fetching JWKS from {}", document.jwks_uri);
    let jwks = fetch_only(&document.jwks_uri).await?;

    rocket::build()
        .manage(JwksState {
            jwks: RwLock::new(jwks),
            audiences: kc_audiences.collect(),
        })
        .mount("/", routes![health])
        .mount("/api", routes![register_agent])
        .launch()
        .await?;

    Ok(())
}

