use std::sync::Arc;

use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use tokio::fs;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, info};
use wazuh_cert_oauth2_model::models::errors::AppResult;

use super::CrlBackend;
use super::CrlWatchValue;
use super::RevocationEntry;
use super::compute_etag;
use super::ffi;

pub(super) enum Command {
    Rebuild {
        ca_cert: Arc<X509>,
        ca_key: Arc<PKey<Private>>,
        entries_snapshot: Vec<RevocationEntry>,
        respond_to: oneshot::Sender<AppResult<()>>,
    },
}

pub(super) fn spawn_crl_worker(
    backend: CrlBackend,
    mut rx: mpsc::Receiver<Command>,
    rebuild_notify: watch::Sender<CrlWatchValue>,
) {
    tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                Command::Rebuild {
                    ca_cert,
                    ca_key,
                    entries_snapshot,
                    respond_to,
                } => {
                    let res = apply_rebuild(
                        &backend,
                        &ca_cert,
                        &ca_key,
                        entries_snapshot,
                        &rebuild_notify,
                    )
                    .await;
                    let _ = respond_to.send(res);
                }
            }
        }
    });
}

async fn apply_rebuild(
    backend: &CrlBackend,
    ca_cert: &X509,
    ca_key: &PKey<Private>,
    entries_snapshot: Vec<RevocationEntry>,
    rebuild_notify: &watch::Sender<CrlWatchValue>,
) -> AppResult<()> {
    info!(
        "Rebuilding CRL with {} revocation entries",
        entries_snapshot.len()
    );
    let started = std::time::Instant::now();
    let bytes: Vec<u8> = unsafe {
        let crl = ffi::create_crl()?;
        ffi::set_version_and_issuer(crl, ca_cert.as_ref())?;
        ffi::set_times_now_and_next(crl)?;
        ffi::add_revocations(crl, entries_snapshot)?;
        ffi::sort_and_sign(crl, ca_key)?;
        ffi::encode_der_and_free(crl)?
    };

    persist(backend, &bytes).await?;

    let etag = compute_etag(&bytes);
    info!("CRL updated (took {:?}, etag={})", started.elapsed(), etag);

    rebuild_notify.send_replace((etag, Some(Arc::new(bytes))));

    Ok(())
}

/// Persist the signed CRL to the configured backend.
async fn persist(backend: &CrlBackend, bytes: &[u8]) -> AppResult<()> {
    match backend {
        CrlBackend::File(path) => {
            let tmp = path.with_extension("crl.tmp");
            debug!(
                "Writing CRL ({} bytes) to temporary file: {}",
                bytes.len(),
                tmp.display()
            );
            fs::write(&tmp, bytes).await?;
            fs::rename(tmp, path).await?;
            info!("CRL written to {}", path.display());
        }
        CrlBackend::Postgres(pool) => {
            let etag = compute_etag(bytes);
            let mut tx = pool.begin().await?;
            // Atomically bump the generation counter on conflict.
            sqlx::query(
                "INSERT INTO crl_cache (id, der, etag, generation) VALUES (1, $1, $2, 1)
                 ON CONFLICT (id) DO UPDATE SET
                   der = EXCLUDED.der,
                   etag = EXCLUDED.etag,
                   generation = crl_cache.generation + 1,
                   updated_at = now()",
            )
            .bind(bytes)
            .bind(&etag)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            // Notify other replicas to refresh their local cache.
            let _ = sqlx::query("NOTIFY crl_changed").execute(pool).await;
            info!("CRL persisted to crl_cache (etag={})", etag);
        }
    }
    Ok(())
}
