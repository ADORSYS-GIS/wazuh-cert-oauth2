use anyhow::Result;
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

#[derive(Clone)]
pub struct Ledger {
    inner: Arc<RwLock<Vec<LedgerEntry>>>,
    tx: mpsc::Sender<worker::Command>,
}

impl Ledger {
    pub async fn new(path: PathBuf) -> Result<Self> {
        let entries = worker::load_entries(&path).await?;

        let inner = Arc::new(RwLock::new(entries));
        let (tx, rx) = mpsc::channel::<worker::Command>(100);
        worker::spawn_ledger_worker(inner.clone(), path.clone(), rx);

        Ok(Self { inner, tx })
    }

    pub async fn record_issued(&self, subject: String, serial_hex: String) -> Result<()> {
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
                respond_to: tx,
            })
            .await
            .map_err(|e| anyhow::anyhow!("ledger writer dropped: {}", e))?;
        rx.await
            .map_err(|e| anyhow::anyhow!("ledger writer closed: {}", e))??;
        Ok(())
    }

    pub async fn mark_revoked(&self, serial_hex: String, reason: Option<String>) -> Result<()> {
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
            .map_err(|e| anyhow::anyhow!("ledger writer dropped: {}", e))?;
        rx.await
            .map_err(|e| anyhow::anyhow!("ledger writer closed: {}", e))??;
        Ok(())
    }

    pub async fn find_by_subject(&self, subject: &str) -> Vec<LedgerEntry> {
        self.inner
            .read()
            .await
            .iter()
            .filter(|e| e.subject == subject)
            .cloned()
            .collect()
    }

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
