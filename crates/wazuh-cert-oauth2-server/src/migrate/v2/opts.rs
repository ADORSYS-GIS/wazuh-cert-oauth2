use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(about = "One-time import of the CSV ledger into PostgreSQL")]
pub struct MigrateV2Opt {
    /// Path to the CSV ledger to import.
    #[arg(long, env = "INPUT_LEDGER_PATH", default_value = "/data/ledger.csv")]
    pub input: String,

    /// PostgreSQL connection string (system of record).
    #[arg(long, env = "DATABASE_URL", required = true)]
    pub database_url: String,
}
