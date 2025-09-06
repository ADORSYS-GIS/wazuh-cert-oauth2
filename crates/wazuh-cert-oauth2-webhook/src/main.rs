#[macro_use]
extern crate rocket;

use anyhow::*;
use clap::Parser;
use env_logger::{Builder, Env};
use log::info;
use mimalloc::MiMalloc;

mod bootstrap;
mod handlers;
mod models;
mod opts;
mod state;

use crate::bootstrap::{build_state, launch_rocket, spawn_spool_bg};
use crate::opts::Opt;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[rocket::main]
async fn main() -> Result<()> {
    Builder::from_env(Env::default().default_filter_or("info")).init();
    info!("starting webhook");
    let opt = Opt::parse();
    let state = build_state(&opt)?;
    spawn_spool_bg(state.clone());
    launch_rocket(state).await
}
