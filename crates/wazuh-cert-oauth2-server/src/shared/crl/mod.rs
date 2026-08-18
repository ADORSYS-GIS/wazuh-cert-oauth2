use std::path::PathBuf;
use std::sync::Arc;

use openssl::pkey::PKey;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::fs;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, info};
use wazuh_cert_oauth2_model::models::errors::{AppError, AppResult};

/// ETag string paired with an optional cached CRL body.
/// `None` means no valid CRL is loaded (cold start or failed rebuild).
type CrlWatchValue = (String, Option<Arc<Vec<u8>>>);

mod ffi;
mod postgres;
mod worker;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    pub serial_hex: String,
    pub reason: Option<String>,
    pub revoked_at_unix: u64,
}

/// Compute a SHA-256 ETag from arbitrary bytes.
pub fn compute_etag(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

/// Generate a random per-process replica id, used to tag `crl_changed`
/// notifications so a replica can skip its own redundant cache reload.
fn generate_replica_id() -> String {
    use rand::TryRng;
    let mut buf = [0u8; 8];
    rand::rng()
        .try_fill_bytes(&mut buf)
        .expect("thread rng should not fail");
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Where the CRL artifact is persisted.
///
/// - [`CrlBackend::File`]: local-dev / bootstrap fallback (writes DER to disk).
/// - [`CrlBackend::Postgres`]: shared `crl_cache` table + `NOTIFY crl_changed`
///   so multiple replicas serve a consistent CRL.
#[derive(Clone)]
pub enum CrlBackend {
    File(PathBuf),
    Postgres(PgPool),
}

#[derive(Clone)]
pub struct CrlState {
    backend: CrlBackend,
    tx: mpsc::Sender<worker::Command>,
    rebuild_notify: watch::Sender<CrlWatchValue>,
}

impl CrlState {
    #[tracing::instrument(skip(backend))]
    pub async fn new(backend: CrlBackend) -> AppResult<Self> {
        match &backend {
            CrlBackend::File(path) => {
                info!("Initialized CrlState (file) with path: {}", path.display())
            }
            CrlBackend::Postgres(_) => info!("Initialized CrlState (postgres)"),
        }
        let (tx, rx) = mpsc::channel::<worker::Command>(32);

        let (initial_etag, initial_body) = Self::compute_initial(&backend).await?;
        let (rebuild_tx, _) = watch::channel((initial_etag, initial_body));
        let replica_id = generate_replica_id();
        worker::spawn_crl_worker(backend.clone(), replica_id.clone(), rx, rebuild_tx.clone());

        if let CrlBackend::Postgres(pool) = &backend {
            postgres::spawn_crl_listener(pool.clone(), replica_id, rebuild_tx.clone());
        }

        Ok(Self {
            backend,
            tx,
            rebuild_notify: rebuild_tx,
        })
    }

    /// Read the current CRL bytes from the backend.
    ///
    /// Returns `Ok(Vec::new())` when no CRL is available (file missing or no
    /// cache row) so callers can trigger an on-demand rebuild.
    #[tracing::instrument(skip(self))]
    pub async fn read_crl(&self) -> AppResult<Vec<u8>> {
        match &self.backend {
            CrlBackend::File(path) => {
                debug!("Reading CRL file from: {}", path.display());
                match fs::read(path).await {
                    Ok(bytes) => {
                        debug!("Read CRL file ({} bytes)", bytes.len());
                        Ok(bytes)
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
                    Err(e) => Err(e.into()),
                }
            }
            CrlBackend::Postgres(pool) => {
                debug!("Reading CRL from cache");
                match postgres::load_crl_from_cache(pool).await {
                    Ok(Some((_, body))) => Ok(body.to_vec()),
                    Ok(None) => Ok(Vec::new()),
                    Err(e) => Err(e),
                }
            }
        }
    }

    /// Subscribe to CRL rebuild notifications.
    ///
    /// Returns a [`watch::Receiver`] that is notified whenever the CRL is
    /// rebuilt (whether triggered by a long-poll client, a revocation
    /// request, or a `crl_changed` notification from another replica). The
    /// long-poll handler uses this to hold the connection open until the
    /// ETag changes or a timeout elapses.
    pub fn subscribe_rebuild(&self) -> watch::Receiver<CrlWatchValue> {
        self.rebuild_notify.subscribe()
    }

    async fn compute_initial(backend: &CrlBackend) -> AppResult<CrlWatchValue> {
        match backend {
            CrlBackend::File(path) => match fs::read(path).await {
                Ok(bytes) => Ok((compute_etag(&bytes), Some(Arc::new(bytes)))),
                // Missing file is a cold start (empty CRL); other I/O errors
                // are real failures and should surface rather than silently
                // starting with an empty CRL.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((String::new(), None)),
                Err(e) => Err(e.into()),
            },
            CrlBackend::Postgres(pool) => match postgres::load_crl_from_cache(pool).await {
                Ok(Some((etag, body))) => Ok((etag, Some(body))),
                Ok(None) => Ok((String::new(), None)),
                Err(e) => Err(e),
            },
        }
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
            .map_err(|e| AppError::UpstreamError(format!("crl worker dropped: {}", e)))?;
        rx_done
            .await
            .map_err(|e| AppError::UpstreamError(format!("crl worker closed: {}", e)))??;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::hash::MessageDigest;
    use openssl::pkey::{PKey, Private};
    use openssl::rsa::Rsa;
    use openssl::x509::{X509, X509NameBuilder};

    /// Connect to a real Postgres for integration tests. Skips when
    /// `TEST_DATABASE_URL` is not set (e.g. plain `cargo test`).
    async fn test_pool() -> Option<PgPool> {
        let url = match std::env::var("TEST_DATABASE_URL") {
            Ok(u) => u,
            Err(_) => {
                eprintln!("TEST_DATABASE_URL not set; skipping CRL Postgres test");
                return None;
            }
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(20)
            .connect(&url)
            .await
            .expect("connect to test database");
        sqlx::migrate!().run(&pool).await.expect("run migrations");
        Some(pool)
    }

    fn test_ca() -> (X509, PKey<Private>) {
        let rsa = Rsa::generate(2048).expect("generate rsa");
        let key = PKey::from_rsa(rsa).expect("pkey from rsa");
        let mut name_builder = X509NameBuilder::new().expect("name builder");
        name_builder
            .append_entry_by_text("CN", "test-ca")
            .expect("append cn");
        let name = name_builder.build();
        let mut builder = X509::builder().expect("x509 builder");
        builder.set_version(2).expect("set version");
        builder.set_subject_name(&name).expect("set subject");
        builder.set_issuer_name(&name).expect("set issuer");
        builder.set_pubkey(&key).expect("set pubkey");
        builder.sign(&key, MessageDigest::sha256()).expect("sign");
        (builder.build(), key)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn postgres_crl_rebuild_populates_cache_and_notifies() {
        let Some(pool) = test_pool().await else {
            return;
        };
        // Reset the single-row cache so generation starts at 1 (the table
        // persists across test runs).
        sqlx::query("DELETE FROM crl_cache")
            .execute(&pool)
            .await
            .expect("clear crl_cache");
        let (ca_cert, ca_key) = test_ca();

        let state = CrlState::new(CrlBackend::Postgres(pool.clone()))
            .await
            .expect("crl state");

        let mut rx = state.subscribe_rebuild();
        let entries = vec![RevocationEntry {
            serial_hex: "ABC123".to_string(),
            reason: Some("test".to_string()),
            revoked_at_unix: 100,
        }];
        state
            .request_rebuild(Arc::new(ca_cert), Arc::new(ca_key), entries)
            .await
            .expect("rebuild should succeed");

        // The crl_cache table should now hold the signed DER + etag + generation.
        let row: Option<(Vec<u8>, String, i64)> =
            sqlx::query_as("SELECT der, etag, generation FROM crl_cache WHERE id = 1")
                .fetch_optional(&pool)
                .await
                .expect("query crl_cache");
        let (der, etag, generation) = row.expect("crl_cache row present");
        assert_eq!(generation, 1);
        assert_eq!(etag, compute_etag(&der));

        // The local watch channel should carry the new body. Scope the borrow
        // so the watch read-lock is released before the next rebuild (a held
        // borrow would block the worker's send_replace).
        {
            let (_, body) = &*rx.borrow_and_update();
            assert!(body.is_some(), "watch channel should have a CRL body");
        }

        // A second rebuild bumps the generation counter.
        let (ca_cert, ca_key) = test_ca();
        state
            .request_rebuild(Arc::new(ca_cert), Arc::new(ca_key), vec![])
            .await
            .expect("second rebuild");
        let gen2: i64 = sqlx::query_scalar("SELECT generation FROM crl_cache WHERE id = 1")
            .fetch_one(&pool)
            .await
            .expect("query generation");
        assert_eq!(gen2, 2, "generation should increment on each rebuild");
    }
}
