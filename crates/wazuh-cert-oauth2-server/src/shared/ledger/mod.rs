use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use wazuh_cert_oauth2_model::models::errors::AppResult;
pub use wazuh_cert_oauth2_model::models::ledger_entry::LedgerEntry;

mod commands;
pub(crate) mod csv;
mod csv_store;
pub(crate) mod csv_utils;
mod loader;
mod postgres;
mod worker;

/// Storage backend for the issuance ledger.
///
/// The public [`Ledger`] API is backend-agnostic; the CSV implementation is
/// kept for local-dev / tests / one-time import, while PostgreSQL is the
/// system of record for multi-replica deployments.
#[async_trait]
pub trait LedgerStore: Send + Sync {
    async fn record_issued(
        &self,
        subject: String,
        serial_hex: String,
        issued_at_unix: u64,
        issuer: Option<String>,
        realm: Option<String>,
        wazuh_agent_name: Option<String>,
    ) -> AppResult<()>;

    async fn mark_revoked(
        &self,
        serial_hex: String,
        reason: Option<String>,
        revoked_at_unix: u64,
    ) -> AppResult<()>;

    /// Revoke all active certs for a subject (auto-rotate).
    ///
    /// Returns `None` when the subject has no active cert, `Some(names)` when
    /// active certs were revoked (names = the Wazuh agent names that were
    /// active, for eviction notification). When `overwrite` is false and an
    /// active cert exists, returns [`AppError::Conflict`].
    async fn check_and_revoke_active(
        &self,
        subject: String,
        overwrite: bool,
        revoked_at_unix: u64,
    ) -> AppResult<Option<Vec<String>>>;

    async fn find_by_subject(&self, subject: &str) -> AppResult<Vec<LedgerEntry>>;
    async fn find_active(&self) -> AppResult<Vec<LedgerEntry>>;
    async fn find_revoked(&self) -> AppResult<Vec<LedgerEntry>>;
    async fn find_all(&self) -> AppResult<Vec<LedgerEntry>>;
}

/// Selects which ledger backend to use.
pub enum LedgerBackend {
    /// On-disk CSV (local-dev / tests / emergency fallback).
    Csv(PathBuf),
    /// PostgreSQL (system of record for multi-replica).
    Postgres(sqlx::PgPool),
}

#[derive(Clone)]
pub struct Ledger {
    store: Arc<dyn LedgerStore>,
}

impl Ledger {
    #[tracing::instrument(skip(backend))]
    pub async fn new(backend: LedgerBackend) -> AppResult<Self> {
        let store: Arc<dyn LedgerStore> = match backend {
            LedgerBackend::Csv(path) => Arc::new(csv_store::CsvLedgerStore::new(path).await?),
            LedgerBackend::Postgres(pool) => Arc::new(postgres::PostgresLedgerStore::new(pool)),
        };
        Ok(Self { store })
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    #[tracing::instrument(skip(self))]
    pub async fn record_issued(
        &self,
        subject: String,
        serial_hex: String,
        issuer: Option<String>,
        realm: Option<String>,
        wazuh_agent_name: Option<String>,
    ) -> AppResult<()> {
        self.store
            .record_issued(
                subject,
                serial_hex,
                Self::now(),
                issuer,
                realm,
                wazuh_agent_name,
            )
            .await
    }

    #[tracing::instrument(skip(self))]
    pub async fn mark_revoked(&self, serial_hex: String, reason: Option<String>) -> AppResult<()> {
        self.store
            .mark_revoked(serial_hex, reason, Self::now())
            .await
    }

    #[tracing::instrument(skip(self))]
    pub async fn find_by_subject(&self, subject: &str) -> AppResult<Vec<LedgerEntry>> {
        self.store.find_by_subject(subject).await
    }

    #[tracing::instrument(skip(self))]
    pub async fn check_and_revoke_active(
        &self,
        subject: String,
        overwrite: bool,
    ) -> AppResult<Option<Vec<String>>> {
        self.store
            .check_and_revoke_active(subject, overwrite, Self::now())
            .await
    }

    #[tracing::instrument(skip(self))]
    pub async fn find_active(&self) -> AppResult<Vec<LedgerEntry>> {
        self.store.find_active().await
    }

    #[tracing::instrument(skip(self))]
    pub async fn find_revoked(&self) -> AppResult<Vec<LedgerEntry>> {
        self.store.find_revoked().await
    }

    #[tracing::instrument(skip(self))]
    pub async fn find_all(&self) -> AppResult<Vec<LedgerEntry>> {
        self.store.find_all().await
    }

    #[tracing::instrument(skip(self))]
    pub async fn revoked_as_revocations(
        &self,
    ) -> AppResult<Vec<crate::shared::crl::RevocationEntry>> {
        Ok(self
            .store
            .find_revoked()
            .await?
            .into_iter()
            .map(|e| crate::shared::crl::RevocationEntry {
                serial_hex: e.serial_hex,
                reason: e.reason,
                revoked_at_unix: e.revoked_at_unix.unwrap_or_default(),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::Ledger;
    use super::LedgerBackend;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::fs;

    fn unique_ledger_path() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        std::env::temp_dir()
            .join(format!("wazuh-ledger-test-{}", nanos))
            .join("ledger.csv")
    }

    async fn csv_ledger(path: PathBuf) -> Ledger {
        let parent = path.parent().expect("path should have parent");
        fs::create_dir_all(parent)
            .await
            .expect("temp dir should exist");
        Ledger::new(LedgerBackend::Csv(path))
            .await
            .expect("ledger should initialize")
    }

    #[tokio::test]
    async fn ledger_records_and_revokes_entries() {
        let path = unique_ledger_path();
        let parent = path.parent().expect("path should have parent");

        let ledger = csv_ledger(path.clone()).await;
        ledger
            .record_issued(
                "subject-a".to_string(),
                "ABCD01".to_string(),
                Some("https://issuer/realms/dev".to_string()),
                Some("dev".to_string()),
                None,
            )
            .await
            .expect("record_issued should succeed");

        let by_subject = ledger
            .find_by_subject("subject-a")
            .await
            .expect("find_by_subject should succeed");
        assert_eq!(by_subject.len(), 1);
        assert_eq!(by_subject[0].serial_hex, "ABCD01");
        assert!(!by_subject[0].revoked);

        ledger
            .mark_revoked("ABCD01".to_string(), Some("manual".to_string()))
            .await
            .expect("mark_revoked should succeed");

        let revocations = ledger
            .revoked_as_revocations()
            .await
            .expect("revoked_as_revocations should succeed");
        assert_eq!(revocations.len(), 1);
        assert_eq!(revocations[0].serial_hex, "ABCD01");
        assert_eq!(revocations[0].reason.as_deref(), Some("manual"));
        assert!(revocations[0].revoked_at_unix > 0);

        let _ = fs::remove_dir_all(parent).await;
    }

    #[tokio::test]
    async fn ledger_revoke_unknown_serial_creates_revoked_stub() {
        let path = unique_ledger_path();
        let parent = path.parent().expect("path should have parent");

        let ledger = csv_ledger(path.clone()).await;
        ledger
            .mark_revoked("UNKNOWN01".to_string(), Some("preemptive".to_string()))
            .await
            .expect("mark_revoked should succeed");

        let revocations = ledger
            .revoked_as_revocations()
            .await
            .expect("revoked_as_revocations should succeed");
        assert_eq!(revocations.len(), 1);
        assert_eq!(revocations[0].serial_hex, "UNKNOWN01");
        assert_eq!(revocations[0].reason.as_deref(), Some("preemptive"));

        let _ = fs::remove_dir_all(parent).await;
    }

    #[tokio::test]
    async fn check_and_revoke_active_returns_true_when_cert_was_revoked() {
        let path = unique_ledger_path();
        let parent = path.parent().expect("path should have parent");

        let ledger = csv_ledger(path.clone()).await;
        ledger
            .record_issued(
                "user-a".to_string(),
                "CERT01".to_string(),
                Some("https://issuer/realms/dev".to_string()),
                Some("dev".to_string()),
                None,
            )
            .await
            .expect("record_issued should succeed");

        // overwrite=true — Some(names) means a cert was revoked; names empty because no agent name stored
        let revoked_names = ledger
            .check_and_revoke_active("user-a".to_string(), true)
            .await
            .expect("check_and_revoke_active should succeed");
        assert!(
            revoked_names.is_some(),
            "expected Some when an active cert was revoked"
        );
        assert!(
            revoked_names.unwrap().is_empty(),
            "no agent name was stored, so names should be empty"
        );

        let active = ledger
            .find_active()
            .await
            .expect("find_active should succeed");
        assert!(
            active.is_empty(),
            "no active certs should remain after auto-rotate"
        );

        let revocations = ledger
            .revoked_as_revocations()
            .await
            .expect("revoked_as_revocations should succeed");
        assert_eq!(revocations.len(), 1);
        assert_eq!(revocations[0].serial_hex, "CERT01");
        assert_eq!(
            revocations[0].reason.as_deref(),
            Some("auto-rotate (one cert per user)")
        );

        let _ = fs::remove_dir_all(parent).await;
    }

    #[tokio::test]
    async fn check_and_revoke_active_returns_false_when_no_active_cert() {
        let path = unique_ledger_path();
        let parent = path.parent().expect("path should have parent");

        let ledger = csv_ledger(path.clone()).await;

        // No certs at all — should return None, not error
        let revoked_names = ledger
            .check_and_revoke_active("user-b".to_string(), true)
            .await
            .expect("check_and_revoke_active should succeed even with no certs");
        assert!(
            revoked_names.is_none(),
            "expected None when no active cert exists"
        );

        let _ = fs::remove_dir_all(parent).await;
    }
}
