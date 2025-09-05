#[macro_use]
extern crate log;

use crate::flow::run_oauth2_flow;
use crate::shared::cli::Opt;
use anyhow::Result;
use clap::Parser;
use env_logger::{Builder, Env};
use wazuh_cert_oauth2_model::models::claims::Claims;
use wazuh_cert_oauth2_model::models::document::DiscoveryDocument;
use wazuh_cert_oauth2_model::services::http_client::HttpClient;
use wazuh_cert_oauth2_model::services::jwks::validate_token;

mod services;
mod flow;
pub mod shared;

/// Entry point: configures logging and runs the app workflow.
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

/// Orchestrates the CSR flow: stop agent, obtain token, validate claims,
/// generate CSR and key, submit CSR, save cert+key, set agent name, restart agent.
async fn app() -> Result<()> {
    match Opt::parse() {
        Opt::OAuth2 { issuer, audience, client_id, client_secret, endpoint, is_service_account, cert_path, key_path, agent_control } => {
            run_oauth2_flow(
                &issuer,
                &audience,
                &client_id,
                client_secret.as_ref(),
                &endpoint,
                is_service_account,
                &cert_path,
                &key_path,
                agent_control,
            ).await
        }
    }
}

// flow moved to `flow.rs`
