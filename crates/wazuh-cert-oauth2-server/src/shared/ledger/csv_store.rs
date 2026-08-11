use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{RwLock, mpsc, oneshot};
use wazuh_cert_oauth2_model::models::errors::{AppError, AppResult};

use super::LedgerEntry;
use super::LedgerStore;
use super::worker;

/// CSV-backed ledger store.
///
/// Kept for local-dev, tests, and as an emergency fallback when no database
/// is configured. Uses the original in-memory `Vec` + single background
/// writer + full-file rewrite on every mutation.
pub struct CsvLedgerStore {
    inner: Arc<RwLock<Vec<LedgerEntry>>>,
    tx: mpsc::Sender<worker::Command>,
}

impl CsvLedgerStore {
    #[tracing::instrument(skip(path))]
    pub async fn new(path: PathBuf) -> AppResult<Self> {
        let entries = worker::load_entries(&path).await?;

        let inner = Arc::new(RwLock::new(entries));
        let (tx, rx) = mpsc::channel::<worker::Command>(100);
        worker::spawn_ledger_worker(inner.clone(), path.clone(), rx);

        Ok(Self { inner, tx })
    }
}

#[async_trait]
impl LedgerStore for CsvLedgerStore {
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
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(worker::Command::RecordIssued {
                subject,
                serial_hex,
                issued_at_unix,
                issuer,
                realm,
                wazuh_agent_name,
                respond_to: tx,
            })
            .await
            .map_err(|e| AppError::UpstreamError(format!("ledger writer dropped: {}", e)))?;
        rx.await
            .map_err(|e| AppError::UpstreamError(format!("ledger writer closed: {}", e)))??;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn mark_revoked(
        &self,
        serial_hex: String,
        reason: Option<String>,
        revoked_at_unix: u64,
    ) -> AppResult<()> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(worker::Command::MarkRevoked {
                serial_hex,
                reason,
                revoked_at_unix,
                respond_to: tx,
            })
            .await
            .map_err(|e| AppError::UpstreamError(format!("ledger writer dropped: {}", e)))?;
        rx.await
            .map_err(|e| AppError::UpstreamError(format!("ledger writer closed: {}", e)))??;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn check_and_revoke_active(
        &self,
        subject: String,
        overwrite: bool,
        revoked_at_unix: u64,
    ) -> AppResult<Option<Vec<String>>> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(worker::Command::CheckAndRevokeActive {
                subject,
                overwrite,
                revoked_at_unix,
                respond_to: tx,
            })
            .await
            .map_err(|e| AppError::UpstreamError(format!("ledger writer dropped: {}", e)))?;
        rx.await
            .map_err(|e| AppError::UpstreamError(format!("ledger writer closed: {}", e)))?
    }

    #[tracing::instrument(skip(self))]
    async fn find_by_subject(&self, subject: &str) -> Vec<LedgerEntry> {
        self.inner
            .read()
            .await
            .iter()
            .filter(|e| e.subject == subject)
            .cloned()
            .collect()
    }

    #[tracing::instrument(skip(self))]
    async fn find_active(&self) -> Vec<LedgerEntry> {
        self.inner
            .read()
            .await
            .iter()
            .filter(|e| !e.revoked)
            .cloned()
            .collect()
    }

    #[tracing::instrument(skip(self))]
    async fn find_revoked(&self) -> Vec<LedgerEntry> {
        self.inner
            .read()
            .await
            .iter()
            .filter(|e| e.revoked)
            .cloned()
            .collect()
    }

    #[tracing::instrument(skip(self))]
    async fn find_all(&self) -> Vec<LedgerEntry> {
        self.inner.read().await.clone()
    }
}
