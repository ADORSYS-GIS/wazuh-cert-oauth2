use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use tokio::sync::watch;
use tracing::{debug, error};

use wazuh_cert_oauth2_model::models::errors::AppResult;

use super::CrlWatchValue;

/// Load the latest CRL (DER + etag) from the shared `crl_cache` table.
pub(super) async fn load_crl_from_cache(
    pool: &PgPool,
) -> AppResult<Option<(String, Arc<Vec<u8>>)>> {
    let row: Option<(Vec<u8>, String)> =
        sqlx::query_as("SELECT der, etag FROM crl_cache WHERE id = 1")
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(der, etag)| (etag, Arc::new(der))))
}

/// Background task that listens for `crl_changed` notifications and refreshes
/// this replica's local cache so long-poll clients get the new CRL promptly.
///
/// `replica_id` is this replica's identity; notifications carrying it are this
/// replica's own rebuilds (already reflected in the local watch channel), so
/// they are skipped to avoid a redundant cache reload.
pub(super) fn spawn_crl_listener(
    pool: PgPool,
    replica_id: String,
    rebuild_notify: watch::Sender<CrlWatchValue>,
) {
    tokio::spawn(async move {
        // Exponential backoff (capped) for connect/listen retries so a
        // degraded pool isn't hammered with connection attempts.
        let mut backoff = Duration::from_secs(1);
        loop {
            let mut listener = match sqlx::postgres::PgListener::connect_with(&pool).await {
                Ok(l) => {
                    backoff = Duration::from_secs(1);
                    l
                }
                Err(e) => {
                    error!("crl listener connect failed: {}", e);
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                    continue;
                }
            };
            if let Err(e) = listener.listen("crl_changed").await {
                error!("crl listener listen failed: {}", e);
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
                continue;
            }
            backoff = Duration::from_secs(1);
            // Re-sync on (re)connect: notifications committed while the
            // listener was disconnected are missed (NOTIFY is best-effort),
            // so reload the latest CRL from the cache to avoid serving a
            // stale in-memory CRL.
            match load_crl_from_cache(&pool).await {
                Ok(Some((etag, body))) => {
                    debug!("crl listener re-synced from cache (etag={})", etag);
                    rebuild_notify.send_replace((etag, Some(body)));
                }
                Ok(None) => {}
                Err(e) => error!("failed to reload CRL from cache on reconnect: {}", e),
            }
            while let Ok(notification) = listener.recv().await {
                if notification.payload() == replica_id {
                    // Our own rebuild — the worker already updated the watch.
                    continue;
                }
                debug!(
                    "crl_changed notification received: {:?}",
                    notification.payload()
                );
                match load_crl_from_cache(&pool).await {
                    Ok(Some((etag, body))) => {
                        rebuild_notify.send_replace((etag, Some(body)));
                    }
                    Ok(None) => {}
                    Err(e) => error!("failed to reload CRL from cache: {}", e),
                }
            }
        }
    });
}
