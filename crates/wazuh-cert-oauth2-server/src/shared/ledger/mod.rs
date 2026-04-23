use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{RwLock, mpsc, oneshot};

mod commands;
mod csv;
mod csv_utils;
mod loader;
mod types;
mod worker;

pub use types::LedgerEntry;
use wazuh_cert_oauth2_model::models::errors::{AppError, AppResult};

#[derive(Clone)]
pub struct Ledger {
    inner: Arc<RwLock<Vec<LedgerEntry>>>,
    tx: mpsc::Sender<worker::Command>,
}

impl Ledger {
    #[tracing::instrument(skip(path))]
    pub async fn new(path: PathBuf) -> AppResult<Self> {
        let entries = worker::load_entries(&path).await?;

        let inner = Arc::new(RwLock::new(entries));
        let (tx, rx) = mpsc::channel::<worker::Command>(100);
        worker::spawn_ledger_worker(inner.clone(), path.clone(), rx);

        Ok(Self { inner, tx })
    }

    #[tracing::instrument(skip(self))]
    pub async fn record_issued(
        &self,
        subject: String,
        serial_hex: String,
        issuer: Option<String>,
        realm: Option<String>,
    ) -> AppResult<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(worker::Command::RecordIssued {
                subject,
                serial_hex,
                issued_at_unix: now,
                issuer,
                realm,
                respond_to: tx,
            })
            .await
            .map_err(|e| AppError::UpstreamError(format!("ledger writer dropped: {}", e)))?;
        rx.await
            .map_err(|e| AppError::UpstreamError(format!("ledger writer closed: {}", e)))??;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn mark_revoked(&self, serial_hex: String, reason: Option<String>) -> AppResult<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(worker::Command::MarkRevoked {
                serial_hex,
                reason,
                revoked_at_unix: now,
                respond_to: tx,
            })
            .await
            .map_err(|e| AppError::UpstreamError(format!("ledger writer dropped: {}", e)))?;
        rx.await
            .map_err(|e| AppError::UpstreamError(format!("ledger writer closed: {}", e)))??;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn find_by_subject(&self, subject: &str) -> Vec<LedgerEntry> {
        self.inner
            .read()
            .await
            .iter()
            .filter(|e| e.subject == subject)
            .cloned()
            .collect()
    }

    #[tracing::instrument(skip(self))]
    pub async fn revoked_as_revocations(&self) -> Vec<crate::shared::crl::RevocationEntry> {
        self.inner
            .read()
            .await
            .iter()
            .filter(|e| e.revoked)
            .map(|e| crate::shared::crl::RevocationEntry {
                serial_hex: e.serial_hex.clone(),
                reason: e.reason.clone(),
                revoked_at_unix: e.revoked_at_unix.unwrap_or_default(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Ledger;
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

    #[tokio::test]
    async fn ledger_records_and_revokes_entries() {
        let path = unique_ledger_path();
        let parent = path.parent().expect("path should have parent");
        fs::create_dir_all(parent)
            .await
            .expect("temp dir should exist");

        let ledger = Ledger::new(path.clone())
            .await
            .expect("ledger should initialize");
        ledger
            .record_issued(
                "subject-a".to_string(),
                "ABCD01".to_string(),
                Some("https://issuer/realms/dev".to_string()),
                Some("dev".to_string()),
            )
            .await
            .expect("record_issued should succeed");

        let by_subject = ledger.find_by_subject("subject-a").await;
        assert_eq!(by_subject.len(), 1);
        assert_eq!(by_subject[0].serial_hex, "ABCD01");
        assert!(!by_subject[0].revoked);

        ledger
            .mark_revoked("ABCD01".to_string(), Some("manual".to_string()))
            .await
            .expect("mark_revoked should succeed");

        let revocations = ledger.revoked_as_revocations().await;
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
        fs::create_dir_all(parent)
            .await
            .expect("temp dir should exist");

        let ledger = Ledger::new(path.clone())
            .await
            .expect("ledger should initialize");
        ledger
            .mark_revoked("UNKNOWN01".to_string(), Some("preemptive".to_string()))
            .await
            .expect("mark_revoked should succeed");

        let revocations = ledger.revoked_as_revocations().await;
        assert_eq!(revocations.len(), 1);
        assert_eq!(revocations[0].serial_hex, "UNKNOWN01");
        assert_eq!(revocations[0].reason.as_deref(), Some("preemptive"));

        let _ = fs::remove_dir_all(parent).await;
    }
}
