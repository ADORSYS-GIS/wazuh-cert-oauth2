#[macro_use]
extern crate rocket;

use anyhow::*;
use env_logger::{Builder, Env};
use std::time::Duration;

use crate::handlers::crl::{get_crl, get_revocations};
use crate::handlers::health::health;
use crate::handlers::register_agent::register_agent;
use crate::handlers::revoke::revoke;
use crate::models::oidc_state::OidcState;

mod handlers;
mod models;
mod shared;

use crate::models::ca_config::CaProvider;
use crate::shared::crl::CrlState;
use crate::shared::ledger::Ledger;
use crate::shared::opts::Opt;
use clap::Parser;
use mimalloc::MiMalloc;
use wazuh_cert_oauth2_model::services::http_client::HttpClient;

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
        crl_dist_url,
        crl_path,
        ledger_path,
    } = Opt::parse();
    let kc_audiences = kc_audiences.split(",").map(|s| s.to_string());

    // Shared HTTP client service with connection pooling
    let http_client = HttpClient::new_with_defaults()?;

    rocket::build()
        .manage(http_client.clone())
        .manage(OidcState::new(
            oauth_issuer,
            kc_audiences.collect(),
            Duration::from_secs(discovery_ttl_secs),
            Duration::from_secs(jwks_ttl_secs),
            http_client,
        ))
        .manage(CaProvider::new(
            root_ca_path,
            root_ca_key_path,
            Duration::from_secs(ca_cache_ttl_secs),
            crl_dist_url,
        ))
        .manage(Ledger::new(ledger_path.into()).await?)
        .manage(CrlState::new(crl_path.into()).await?)
        .mount("/", routes![health, get_crl])
        .mount("/api", routes![register_agent, revoke, get_revocations])
        .launch()
        .await?;

    Ok(())
}
