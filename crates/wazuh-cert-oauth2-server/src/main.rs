#[macro_use]
extern crate rocket;

use anyhow::*;
use env_logger::{Builder, Env};
use std::time::Duration;


use crate::handlers::health::health;
use crate::handlers::register_agent::register_agent;
use crate::models::oidc_state::OidcState;

mod handlers;
mod models;
mod shared;

use crate::models::ca_config::CaProvider;
use clap::Parser;
use mimalloc::MiMalloc;
use crate::shared::opts::Opt;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[rocket::main]
async fn main() -> Result<()> {
    Builder::from_env(Env::default().default_filter_or("info")).init();

    info!("starting up");

    let Opt {
        oauth_issuer,
        kc_audiences,
        root_ca_path,
        root_ca_key_path,
        discovery_ttl_secs,
        jwks_ttl_secs,
        ca_cache_ttl_secs,
    } = Opt::parse();
    let kc_audiences = kc_audiences.split(",").map(|s| s.to_string());

    rocket::build()
        .manage(OidcState::new(
            oauth_issuer,
            kc_audiences.collect(),
            Duration::from_secs(discovery_ttl_secs),
            Duration::from_secs(jwks_ttl_secs),
        ))
        .manage(CaProvider::new(
            root_ca_path,
            root_ca_key_path,
            Duration::from_secs(ca_cache_ttl_secs),
        ))
        .mount("/", routes![health])
        .mount("/api", routes![register_agent])
        .launch()
        .await?;

    Ok(())
}
