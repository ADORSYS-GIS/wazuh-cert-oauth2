use std::path::PathBuf;

use sqlx::PgPool;
use tracing::{info, warn};
use wazuh_cert_oauth2_model::models::errors::{AppError, AppResult};

use crate::migrate::v2::opts::MigrateV2Opt;
use crate::shared::ledger::csv::parse_csv;

/// One-time import of the CSV ledger into PostgreSQL.
///
/// Reads `ledger.csv`, applies migrations, then bulk-inserts every entry into
/// both `ledger_event` (append-only audit log) and `ledger_entry` (materialized
/// current state) inside a single transaction.
pub async fn run_migration(opt: MigrateV2Opt) -> AppResult<()> {
    let input_path = PathBuf::from(&opt.input);
    if !input_path.exists() {
        return Err(AppError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Input ledger CSV not found: {}", opt.input),
        )));
    }

    let content = tokio::fs::read_to_string(&input_path).await?;
    let entries = parse_csv(&content)?;
    info!("Read {} ledger entries from {}", entries.len(), opt.input);
    if entries.is_empty() {
        return Err(AppError::UpstreamError("No ledger entries found".into()));
    }

    let pool = PgPool::connect(&opt.database_url)
        .await
        .map_err(|e| AppError::UpstreamError(format!("failed to connect to database: {}", e)))?;
    sqlx::migrate!()
        .run(&pool)
        .await
        .map_err(|e| AppError::UpstreamError(format!("failed to run migrations: {}", e)))?;

    let mut tx = pool
        .begin()
        .await
        .map_err(|e| AppError::UpstreamError(format!("failed to begin transaction: {}", e)))?;

    let mut issued = 0usize;
    let mut revoked = 0usize;
    let mut stubs = 0usize;

    for entry in &entries {
        let serial = entry.serial_hex.to_uppercase();
        let event_type = if entry.revoked {
            if entry.subject.is_empty() {
                stubs += 1;
                "STUB_REVOKED"
            } else {
                revoked += 1;
                "REVOKED"
            }
        } else {
            issued += 1;
            "ISSUED"
        };

        sqlx::query(
            "INSERT INTO ledger_event (event_type, subject, serial_hex, issued_at_unix, revoked_at_unix, reason, issuer, realm, wazuh_agent_name)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(event_type)
        .bind(&entry.subject)
        .bind(&serial)
        .bind(entry.issued_at_unix as i64)
        .bind(entry.revoked_at_unix.map(|v| v as i64))
        .bind(&entry.reason)
        .bind(&entry.issuer)
        .bind(&entry.realm)
        .bind(&entry.wazuh_agent_name)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::UpstreamError(format!("failed to insert ledger_event: {}", e)))?;

        sqlx::query(
            "INSERT INTO ledger_entry (serial_hex, subject, issued_at_unix, revoked, revoked_at_unix, reason, issuer, realm, wazuh_agent_name)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (serial_hex) DO UPDATE SET
               subject = EXCLUDED.subject,
               issued_at_unix = EXCLUDED.issued_at_unix,
               revoked = EXCLUDED.revoked,
               revoked_at_unix = EXCLUDED.revoked_at_unix,
               reason = EXCLUDED.reason,
               issuer = EXCLUDED.issuer,
               realm = EXCLUDED.realm,
               wazuh_agent_name = EXCLUDED.wazuh_agent_name,
               updated_at = now()",
        )
        .bind(&serial)
        .bind(&entry.subject)
        .bind(entry.issued_at_unix as i64)
        .bind(entry.revoked)
        .bind(entry.revoked_at_unix.map(|v| v as i64))
        .bind(&entry.reason)
        .bind(&entry.issuer)
        .bind(&entry.realm)
        .bind(&entry.wazuh_agent_name)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::UpstreamError(format!("failed to insert ledger_entry: {}", e)))?;
    }

    tx.commit()
        .await
        .map_err(|e| AppError::UpstreamError(format!("failed to commit transaction: {}", e)))?;

    info!(
        "Import complete: {} issued, {} revoked, {} revoke-stubs",
        issued, revoked, stubs
    );
    if stubs > 0 {
        warn!(
            "{} revoke-stub entries (unknown serial, empty subject) were imported",
            stubs
        );
    }
    Ok(())
}
