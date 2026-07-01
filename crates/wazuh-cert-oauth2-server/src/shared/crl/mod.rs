use std::path::PathBuf;
use std::sync::Arc;

use openssl::pkey::PKey;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::fs;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, info};
use wazuh_cert_oauth2_model::models::errors::AppResult;

mod ffi;
mod worker;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    pub serial_hex: String,
    pub reason: Option<String>,
    pub revoked_at_unix: u64,
}

#[derive(Clone)]
pub struct CrlState {
    crl_file_path: PathBuf,
    tx: mpsc::Sender<worker::Command>,
    rebuild_notify: Arc<watch::Sender<String>>,
}

impl CrlState {
    #[tracing::instrument(skip(crl_file_path))]
    pub async fn new(crl_file_path: PathBuf) -> AppResult<Self> {
        info!(
            "Initialized CrlState with path: {}",
            crl_file_path.display()
        );
        let (tx, rx) = mpsc::channel::<worker::Command>(32);

        let initial_etag = Self::compute_etag_from_file(&crl_file_path).await;
        let (rebuild_tx, _) = watch::channel(initial_etag);
        worker::spawn_crl_worker(crl_file_path.clone(), rx, rebuild_tx.clone());

        Ok(Self {
            crl_file_path,
            tx,
            rebuild_notify: Arc::new(rebuild_tx),
        })
    }

    #[tracing::instrument(skip(self))]
    pub async fn read_crl_file(&self) -> AppResult<Vec<u8>> {
        debug!("Reading CRL file from: {}", self.crl_file_path.display());
        let bytes = fs::read(&self.crl_file_path).await?;
        debug!("Read CRL file ({} bytes)", bytes.len());
        Ok(bytes)
    }

    pub fn subscribe_rebuild(&self) -> watch::Receiver<String> {
        self.rebuild_notify.subscribe()
    }

    pub fn current_etag(&self) -> String {
        self.rebuild_notify.borrow().clone()
    }

    async fn compute_etag_from_file(path: &PathBuf) -> String {
        match fs::read(path).await {
            Ok(bytes) => Self::compute_etag(&bytes),
            Err(_) => String::new(),
        }
    }

    fn compute_etag(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        format!("{:x}", hasher.finalize())
    }

    #[tracing::instrument(skip(self, ca_cert, ca_key, entries_snapshot))]
    pub async fn request_rebuild(
        &self,
        ca_cert: Arc<X509>,
        ca_key: Arc<PKey<openssl::pkey::Private>>,
        entries_snapshot: Vec<RevocationEntry>,
    ) -> AppResult<()> {
        let (tx_done, rx_done) = oneshot::channel();
        self.tx
            .send(worker::Command::Rebuild {
                ca_cert,
                ca_key,
                entries_snapshot,
                respond_to: tx_done,
            })
            .await
            .map_err(|e| {
                wazuh_cert_oauth2_model::models::errors::AppError::UpstreamError(format!(
                    "crl worker dropped: {}",
                    e
                ))
            })?;
        let _etag = rx_done.await.map_err(|e| {
            wazuh_cert_oauth2_model::models::errors::AppError::UpstreamError(format!(
                "crl worker closed: {}",
                e
            ))
        })??;

        Ok(())
    }
}
