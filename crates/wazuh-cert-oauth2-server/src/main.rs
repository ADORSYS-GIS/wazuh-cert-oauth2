#[macro_use]
extern crate rocket;

use std::time::Duration;

use crate::handlers::crl::{get_crl, get_revocations};
use crate::handlers::health::health;
use crate::handlers::register_agent::register_agent;
use crate::handlers::revoke::revoke;
use crate::models::oidc_state::OidcState;

mod handlers;
mod models;
mod shared;
mod tracing_fairing;

use crate::models::ca_config::CaProvider;
use crate::shared::crl::CrlState;
use crate::shared::ledger::Ledger;
use crate::shared::opts::Opt;
use clap::Parser;
use mimalloc::MiMalloc;
use tracing::info;
use wazuh_cert_oauth2_model::models::errors::{AppError, AppResult};
use wazuh_cert_oauth2_model::services::http_client::HttpClient;
use wazuh_cert_oauth2_model::services::otel::setup_telemetry;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[rocket::main]
async fn main() -> AppResult<()> {
    setup_telemetry("wazuh-cert-oauth2-server")?;

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
    } = Opt::try_parse()?;
    let kc_audiences = kc_audiences.map(|a| a.split(",").map(|s| s.to_string()).collect());

    // Shared HTTP client service with connection pooling
    let http_client = HttpClient::new_with_defaults()?;

    rocket::build()
        .attach(tracing_fairing::telemetry_fairing())
        .manage(http_client.clone())
        .manage(OidcState::new(
            oauth_issuer,
            kc_audiences,
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
        .await
        .map_err(|e| AppError::RocketError(Box::new(e)))?;

    Ok(())
}
