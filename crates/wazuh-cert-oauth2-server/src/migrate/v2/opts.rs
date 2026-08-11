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

    /// Allow re-importing into a database that already contains ledger data.
    /// Without this flag the import refuses to run if `ledger_entry` is
    /// non-empty, to avoid duplicating `ledger_event` audit rows on re-runs.
    #[arg(long, env = "MIGRATE_V2_FORCE", default_value_t = false)]
    pub force: bool,
}
