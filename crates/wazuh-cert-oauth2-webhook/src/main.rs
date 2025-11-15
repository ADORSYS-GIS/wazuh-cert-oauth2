#[macro_use]
extern crate rocket;

use clap::Parser;
use mimalloc::MiMalloc;
use tracing::info;
use wazuh_cert_oauth2_model::models::errors::AppResult;

mod bootstrap;
mod handlers;
mod models;
mod opts;
mod state;

use crate::bootstrap::{build_state, launch_rocket, spawn_spool_bg};
use crate::opts::Opt;
use wazuh_cert_oauth2_model::services::logging::setup_logging;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[rocket::main]
async fn main() -> AppResult<()> {
    setup_logging("wazuh-cert-oauth2-webhook")?;

    info!("starting webhook");
    let opt = Opt::try_parse()?;
    let state = build_state(&opt)?;
    spawn_spool_bg(state.clone());
    launch_rocket(state).await
}
