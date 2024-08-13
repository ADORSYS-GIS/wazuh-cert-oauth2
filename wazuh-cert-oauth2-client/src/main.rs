#[macro_use]
extern crate log;

use std::fs::File;

use anyhow::*;
use structopt::StructOpt;

use crate::cli::Opt;

mod command;
mod errors;
mod cli;
mod services;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    info!("starting up");

    match Opt::from_args() {
        Opt::OAuth2 { .. } => {

        }
    }
}
