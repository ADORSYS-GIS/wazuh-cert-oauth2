#[macro_use]
extern crate log;

use crate::flow::{FlowParams, run_oauth2_flow};
use crate::shared::cli::Opt;
use clap::Parser;
use env_logger::{Builder, Env};
use wazuh_cert_oauth2_model::models::errors::AppResult;

mod flow;
mod services;
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
async fn app() -> AppResult<()> {
    match Opt::try_parse() {
        Ok(opt) => {
            let params = FlowParams::from(opt);
            run_oauth2_flow(&params).await?;

            Ok(())
        }
        _ => Ok(()),
    }
}

// flow moved to `flow.rs`
