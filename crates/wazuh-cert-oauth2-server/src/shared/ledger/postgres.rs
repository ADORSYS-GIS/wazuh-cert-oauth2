use async_trait::async_trait;
use sqlx::PgPool;
use sqlx::Row;
use wazuh_cert_oauth2_model::models::errors::{AppError, AppResult};
use wazuh_cert_oauth2_model::models::ledger_entry::CERTIFICATE_VALIDITY_DAYS;

use super::LedgerEntry;
use super::LedgerStore;

/// PostgreSQL-backed ledger store (system of record for multi-replica).
///
/// Writes go through a single transaction that appends to the audit log
/// (`ledger_event`) and materializes current state (`ledger_entry`).
/// `check_and_revoke_active` uses `SELECT ... FOR UPDATE` so auto-rotate is
/// atomic across replicas.
pub struct PostgresLedgerStore {
    pool: PgPool,
}

impl PostgresLedgerStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn normalize_serial(serial: &str) -> String {
    serial.to_uppercase()
}

fn map_row(row: &sqlx::postgres::PgRow) -> LedgerEntry {
    LedgerEntry {
        subject: row.get("subject"),
        serial_hex: row.get("serial_hex"),
        issued_at_unix: row.get::<i64, _>("issued_at_unix") as u64,
        not_after_unix: row
            .get::<Option<i64>, _>("not_after_unix")
            .map(|v| v as u64)
            .unwrap_or_default(),
        revoked: row.get("revoked"),
        revoked_at_unix: row
            .get::<Option<i64>, _>("revoked_at_unix")
            .map(|v| v as u64),
        reason: row.get("reason"),
        issuer: row.get("issuer"),
        realm: row.get("realm"),
        wazuh_agent_name: row.get("wazuh_agent_name"),
    }
}

#[async_trait]
impl LedgerStore for PostgresLedgerStore {
    #[tracing::instrument(skip(self))]
    async fn record_issued(
        &self,
        subject: String,
        serial_hex: String,
        issued_at_unix: u64,
        issuer: Option<String>,
        realm: Option<String>,
        wazuh_agent_name: Option<String>,
    ) -> AppResult<()> {
        let serial = normalize_serial(&serial_hex);
        let not_after_unix = issued_at_unix + CERTIFICATE_VALIDITY_DAYS * 86400;
        let mut tx = self.pool.begin().await?;

        sqlx::query(
            "INSERT INTO ledger_event (event_type, subject, serial_hex, issued_at_unix, not_after_unix, issuer, realm, wazuh_agent_name)
             VALUES ('ISSUED', $1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&subject)
        .bind(&serial)
        .bind(issued_at_unix as i64)
        .bind(not_after_unix as i64)
        .bind(&issuer)
        .bind(&realm)
        .bind(&wazuh_agent_name)
        .execute(&mut *tx)
        .await
        ?;

        sqlx::query(
            "INSERT INTO ledger_entry (serial_hex, subject, issued_at_unix, not_after_unix, revoked, issuer, realm, wazuh_agent_name)
             VALUES ($1, $2, $3, $4, FALSE, $5, $6, $7)
             ON CONFLICT (serial_hex) DO UPDATE SET
               subject = EXCLUDED.subject,
               issued_at_unix = EXCLUDED.issued_at_unix,
               not_after_unix = EXCLUDED.not_after_unix,
               revoked = FALSE,
               revoked_at_unix = NULL,
               reason = NULL,
               issuer = EXCLUDED.issuer,
               realm = EXCLUDED.realm,
               wazuh_agent_name = EXCLUDED.wazuh_agent_name,
               updated_at = now()",
        )
        .bind(&serial)
        .bind(&subject)
        .bind(issued_at_unix as i64)
        .bind(not_after_unix as i64)
        .bind(&issuer)
        .bind(&realm)
        .bind(&wazuh_agent_name)
        .execute(&mut *tx)
        .await
        ?;

        tx.commit().await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn mark_revoked(
        &self,
        serial_hex: String,
        reason: Option<String>,
        revoked_at_unix: u64,
    ) -> AppResult<()> {
        let serial = normalize_serial(&serial_hex);
        let mut tx = self.pool.begin().await?;

        let existing: Option<(bool,)> =
            sqlx::query_as("SELECT revoked FROM ledger_entry WHERE serial_hex = $1 FOR UPDATE")
                .bind(&serial)
                .fetch_optional(&mut *tx)
                .await?;

        match existing {
            Some((true,)) => {
                // Already revoked — no-op (matches CSV behaviour).
                tx.commit().await?;
                Ok(())
            }
            Some((false,)) => {
                sqlx::query(
                    "UPDATE ledger_entry SET revoked = TRUE, revoked_at_unix = $2, reason = $3, updated_at = now()
                     WHERE serial_hex = $1",
                )
                .bind(&serial)
                .bind(revoked_at_unix as i64)
                .bind(&reason)
                .execute(&mut *tx)
                .await
                ?;
                sqlx::query(
                    "INSERT INTO ledger_event (event_type, serial_hex, revoked_at_unix, reason)
                     VALUES ('REVOKED', $1, $2, $3)",
                )
                .bind(&serial)
                .bind(revoked_at_unix as i64)
                .bind(&reason)
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
                Ok(())
            }
            None => {
                // Revoke of an unknown serial — insert a revoked stub.
                sqlx::query(
                    "INSERT INTO ledger_entry (serial_hex, subject, issued_at_unix, revoked, revoked_at_unix, reason)
                     VALUES ($1, '', 0, TRUE, $2, $3)",
                )
                .bind(&serial)
                .bind(revoked_at_unix as i64)
                .bind(&reason)
                .execute(&mut *tx)
                .await
                ?;
                sqlx::query(
                    "INSERT INTO ledger_event (event_type, subject, serial_hex, issued_at_unix, revoked_at_unix, reason)
                     VALUES ('STUB_REVOKED', '', $1, 0, $2, $3)",
                )
                .bind(&serial)
                .bind(revoked_at_unix as i64)
                .bind(&reason)
                .execute(&mut *tx)
                .await
                ?;
                tx.commit().await?;
                Ok(())
            }
        }
    }

    #[tracing::instrument(skip(self))]
    async fn check_and_revoke_active(
        &self,
        subject: String,
        overwrite: bool,
        revoked_at_unix: u64,
    ) -> AppResult<Option<Vec<String>>> {
        let mut tx = self.pool.begin().await?;

        // Expired certificates are not considered "active" — they no longer
        // block re-enrollment (issue #316). COALESCE handles legacy rows where
        // not_after_unix is NULL (never back-filled).
        let now = wazuh_cert_oauth2_model::models::now_unix();
        let rows: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT serial_hex, wazuh_agent_name FROM ledger_entry
             WHERE subject = $1 AND revoked = FALSE
               AND (COALESCE(not_after_unix, 0) = 0 OR not_after_unix > $2)
             FOR UPDATE",
        )
        .bind(&subject)
        .bind(now as i64)
        .fetch_all(&mut *tx)
        .await?;

        if rows.is_empty() {
            tx.commit().await?;
            return Ok(None);
        }

        if !overwrite {
            return Err(AppError::Conflict(
                "User already has an active certificate. Use the --overwrite flag to re-enroll and replace it."
                    .to_string(),
            ));
        }

        let mut old_agent_names = Vec::new();
        for (serial, agent_name) in &rows {
            if let Some(name) = agent_name {
                old_agent_names.push(name.clone());
            }
            sqlx::query(
                "UPDATE ledger_entry SET revoked = TRUE, revoked_at_unix = $2, reason = $3, updated_at = now()
                 WHERE serial_hex = $1",
            )
            .bind(serial)
            .bind(revoked_at_unix as i64)
            .bind("auto-rotate (one cert per user)")
            .execute(&mut *tx)
            .await
            ?;
            sqlx::query(
                "INSERT INTO ledger_event (event_type, subject, serial_hex, revoked_at_unix, reason)
                 VALUES ('REVOKED', $1, $2, $3, $4)",
            )
            .bind(&subject)
            .bind(serial)
            .bind(revoked_at_unix as i64)
            .bind("auto-rotate (one cert per user)")
            .execute(&mut *tx)
            .await
            ?;
        }

        tx.commit().await?;
        Ok(Some(old_agent_names))
    }

    #[tracing::instrument(skip(self))]
    async fn find_by_subject(&self, subject: &str) -> AppResult<Vec<LedgerEntry>> {
        let rows = sqlx::query(
            "SELECT subject, serial_hex, issued_at_unix, not_after_unix, revoked, revoked_at_unix, reason, issuer, realm, wazuh_agent_name
             FROM ledger_entry WHERE subject = $1 ORDER BY issued_at_unix",
        )
        .bind(subject)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(map_row).collect())
    }

    #[tracing::instrument(skip(self))]
    async fn find_active(&self) -> AppResult<Vec<LedgerEntry>> {
        let rows = sqlx::query(
            "SELECT subject, serial_hex, issued_at_unix, not_after_unix, revoked, revoked_at_unix, reason, issuer, realm, wazuh_agent_name
             FROM ledger_entry WHERE revoked = FALSE ORDER BY issued_at_unix",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(map_row).collect())
    }

    #[tracing::instrument(skip(self))]
    async fn find_revoked(&self) -> AppResult<Vec<LedgerEntry>> {
        let rows = sqlx::query(
            "SELECT subject, serial_hex, issued_at_unix, not_after_unix, revoked, revoked_at_unix, reason, issuer, realm, wazuh_agent_name
             FROM ledger_entry WHERE revoked = TRUE ORDER BY issued_at_unix",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(map_row).collect())
    }

    #[tracing::instrument(skip(self))]
    async fn find_all(&self) -> AppResult<Vec<LedgerEntry>> {
        let rows = sqlx::query(
            "SELECT subject, serial_hex, issued_at_unix, not_after_unix, revoked, revoked_at_unix, reason, issuer, realm, wazuh_agent_name
             FROM ledger_entry ORDER BY issued_at_unix",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(map_row).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::PostgresLedgerStore;
    use crate::shared::ledger::LedgerStore;

    /// Connect to a real Postgres for integration tests. Skips when
    /// `TEST_DATABASE_URL` is not set (e.g. plain `cargo test`).
    async fn test_store() -> Option<PostgresLedgerStore> {
        let url = match std::env::var("TEST_DATABASE_URL") {
            Ok(u) => u,
            Err(_) => {
                eprintln!("TEST_DATABASE_URL not set; skipping Postgres integration test");
                return None;
            }
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("connect to test database");
        wazuh_cert_oauth2_model::run_ledger_migrations(&pool)
            .await
            .expect("run migrations");
        Some(PostgresLedgerStore::new(pool))
    }

    /// Unique subject per run so tests are idempotent against a persistent DB.
    fn unique_subject(prefix: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        format!("{prefix}-{}-{nanos}", std::process::id())
    }

    #[tokio::test]
    async fn postgres_records_and_revokes_entries() {
        let Some(store) = test_store().await else {
            return;
        };
        let subject = unique_subject("pg-subject");

        store
            .record_issued(
                subject.clone(),
                "ABCD01".to_string(),
                100,
                Some("https://issuer/realms/dev".to_string()),
                Some("dev".to_string()),
                None,
            )
            .await
            .expect("record_issued should succeed");

        let by_subject = store
            .find_by_subject(&subject)
            .await
            .expect("find_by_subject");
        assert_eq!(by_subject.len(), 1);
        assert_eq!(by_subject[0].serial_hex, "ABCD01");
        assert!(!by_subject[0].revoked);

        store
            .mark_revoked("ABCD01".to_string(), Some("manual".to_string()), 200)
            .await
            .expect("mark_revoked should succeed");

        let revoked = store.find_revoked().await.expect("find_revoked");
        let entry = revoked
            .iter()
            .find(|e| e.serial_hex == "ABCD01")
            .expect("revoked entry present");
        assert_eq!(entry.reason.as_deref(), Some("manual"));
        assert_eq!(entry.revoked_at_unix, Some(200));
    }

    #[tokio::test]
    async fn postgres_revoke_unknown_serial_creates_stub() {
        let Some(store) = test_store().await else {
            return;
        };

        store
            .mark_revoked("UNKNOWN01".to_string(), Some("preemptive".to_string()), 300)
            .await
            .expect("mark_revoked should succeed");

        let revoked = store.find_revoked().await.expect("find_revoked");
        let entry = revoked
            .iter()
            .find(|e| e.serial_hex == "UNKNOWN01")
            .expect("stub present");
        assert_eq!(entry.subject, "");
        assert_eq!(entry.issued_at_unix, 0);
        assert_eq!(entry.reason.as_deref(), Some("preemptive"));
    }

    #[tokio::test]
    async fn postgres_check_and_revoke_active_is_atomic() {
        let Some(store) = test_store().await else {
            return;
        };
        let subject = unique_subject("pg-rotate");

        store
            .record_issued(
                subject.clone(),
                "CERT01".to_string(),
                100,
                None,
                None,
                Some("agent-1".to_string()),
            )
            .await
            .expect("record_issued");

        let names = store
            .check_and_revoke_active(subject.clone(), true, 400)
            .await
            .expect("check_and_revoke_active");
        assert_eq!(names, Some(vec!["agent-1".to_string()]));

        let active = store
            .find_by_subject(&subject)
            .await
            .expect("find_by_subject");
        assert!(
            active.iter().all(|e| e.revoked),
            "no active certs for subject after auto-rotate"
        );

        // Second call with no active certs returns None.
        let again = store
            .check_and_revoke_active(subject.clone(), true, 500)
            .await
            .expect("second call");
        assert_eq!(again, None);
    }

    #[tokio::test]
    async fn postgres_check_and_revoke_active_conflicts_without_overwrite() {
        let Some(store) = test_store().await else {
            return;
        };
        let subject = unique_subject("pg-conflict");

        store
            .record_issued(subject.clone(), "CERT02".to_string(), 100, None, None, None)
            .await
            .expect("record_issued");

        let res = store
            .check_and_revoke_active(subject.clone(), false, 400)
            .await;
        assert!(
            res.is_err(),
            "expected Conflict when overwrite=false and active cert exists"
        );
    }

    #[tokio::test]
    async fn postgres_serial_is_normalized_to_uppercase() {
        let Some(store) = test_store().await else {
            return;
        };
        let subject = unique_subject("pg-case");

        store
            .record_issued(subject.clone(), "abcd02".to_string(), 100, None, None, None)
            .await
            .expect("record_issued");

        let by_subject = store
            .find_by_subject(&subject)
            .await
            .expect("find_by_subject");
        assert_eq!(by_subject.len(), 1);
        assert_eq!(by_subject[0].serial_hex, "ABCD02");
    }
}
