#[macro_use]
extern crate rocket;

use std::env::var;

use anyhow::*;
use log::info;
use tokio::sync::RwLock;

use crate::handlers::health::health;
use crate::handlers::register_agent::register_agent;
use crate::models::jwks_state::JwksState;
use crate::shared::jwks::fetch_jwks;

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


    let kc_host = var("KC_HOST")?;
    let kc_realm = var("KC_REALM")?;
    let jwks_url = format!("{}/realms/{}/protocol/openid-connect/certs", kc_host, kc_realm);

    info!("fetching JWKS from {}", jwks_url);
    let jwks = fetch_jwks(&jwks_url).await.context("failed to fetch JWKS")?;

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

