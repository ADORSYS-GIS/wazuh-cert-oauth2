pub mod models;
pub mod services;

/// Run the ledger migrations against the given pool.
///
/// Migrations live in this crate (shared database for the server and webhook
/// stores). Each store's migrations are in their own subdirectory so a crate
/// only creates the tables for the stores it actually uses. `ignore_missing`
/// lets a store's migrator coexist with the others' applied migrations on the
/// shared database. Gated behind the `postgres` feature so crates that don't
/// use the database (e.g. the client) don't compile the migration machinery.
#[cfg(feature = "postgres")]
pub async fn run_ledger_migrations(pool: &sqlx::PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    let mut migrator = sqlx::migrate!("migrations/ledger");
    migrator.set_ignore_missing(true);
    migrator.run(pool).await
}

/// Run the CRL cache migrations against the given pool.
#[cfg(feature = "postgres")]
pub async fn run_crl_migrations(pool: &sqlx::PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    let mut migrator = sqlx::migrate!("migrations/crl");
    migrator.set_ignore_missing(true);
    migrator.run(pool).await
}

/// Run the webhook spool migrations against the given pool.
#[cfg(feature = "postgres")]
pub async fn run_spool_migrations(pool: &sqlx::PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    let mut migrator = sqlx::migrate!("migrations/spool");
    migrator.set_ignore_missing(true);
    migrator.run(pool).await
}
