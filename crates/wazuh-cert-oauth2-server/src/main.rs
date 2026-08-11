#[macro_use]
extern crate rocket;

use std::time::Duration;

use crate::handlers::crl::{get_crl, get_revocations};
use crate::handlers::crl_fairing::CrlEtagFairing;
use crate::handlers::health::health;
use crate::handlers::ledger::{
    get_active_ledger, get_all_ledger, get_ledger_by_subject, get_revoked_ledger,
};
use crate::handlers::register_agent::register_agent;
use crate::handlers::revoke::revoke;
use crate::models::oidc_state::OidcState;

mod handlers;
mod migrate;
mod models;
mod shared;
use crate::models::ca_config::CaProvider;
use crate::shared::crl::CrlState;
use crate::shared::ledger::{Ledger, LedgerBackend};
use crate::shared::opts::{Command, Opt, ServeOpt};
use clap::Parser;
use mimalloc::MiMalloc;
use tracing::info;
use wazuh_cert_oauth2_model::models::errors::{AppError, AppResult};
use wazuh_cert_oauth2_model::services::http_client::HttpClient;
use wazuh_cert_oauth2_model::services::logging::setup_logging;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[rocket::main]
async fn main() -> AppResult<()> {
    setup_logging("wazuh-cert-oauth2-server")?;

    info!("starting up");

    let opt = match Opt::try_parse() {
        Ok(opt) => opt,
        Err(e) => e.exit(),
    };

    match opt.command {
        Command::Migrate(migrate_opt) => {
            migrate::v1::runner::run_migration(migrate_opt).await?;
            Ok(())
        }
        Command::MigrateV2(migrate_opt) => {
            migrate::v2::runner::run_migration(migrate_opt).await?;
            Ok(())
        }
        Command::Serve(serve_opt) => run_server(serve_opt).await,
    }
}

async fn run_server(opt: ServeOpt) -> AppResult<()> {
    let ServeOpt {
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
        database_url,
        webhook_base_url,
        webhook_bearer_token,
    } = opt;
    let kc_audiences = kc_audiences.map(|a| a.split(",").map(|s| s.to_string()).collect());

    // Shared HTTP client service with connection pooling
    let http_client = HttpClient::new_with_defaults()?;

    // Ledger backend: PostgreSQL when DATABASE_URL is set (system of record),
    // otherwise fall back to the on-disk CSV ledger for local-dev / tests.
    // An empty DATABASE_URL (e.g. a chart default of '') is treated as unset.
    let ledger = match database_url.as_deref().map(str::trim) {
        Some(url) if !url.is_empty() => {
            info!("using PostgreSQL ledger backend");
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(5)
                .connect(url)
                .await
                .map_err(|e| {
                    AppError::UpstreamError(format!("failed to connect to database: {}", e))
                })?;
            sqlx::migrate!()
                .run(&pool)
                .await
                .map_err(|e| AppError::UpstreamError(format!("failed to run migrations: {}", e)))?;
            Ledger::new(LedgerBackend::Postgres(pool)).await?
        }
        _ => {
            info!("using CSV ledger backend (no DATABASE_URL configured)");
            Ledger::new(LedgerBackend::Csv(ledger_path.into())).await?
        }
    };

    let webhook_notifier = webhook_base_url.map(|base_url| {
        crate::shared::webhook_notifier::WebhookNotifier::new(
            http_client.clone(),
            base_url,
            webhook_bearer_token,
        )
    });

    rocket::build()
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
        .manage(ledger)
        .manage(CrlState::new(crl_path.into()).await?)
        .manage(webhook_notifier)
        .attach(CrlEtagFairing)
        .mount("/", routes![health, get_crl])
        .mount(
            "/api",
            routes![
                register_agent,
                revoke,
                get_revocations,
                get_all_ledger,
                get_active_ledger,
                get_revoked_ledger,
                get_ledger_by_subject
            ],
        )
        .launch()
        .await
        .map_err(|e| AppError::RocketError(Box::new(e)))?;

    Ok(())
}
