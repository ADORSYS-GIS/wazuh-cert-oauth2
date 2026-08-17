use std::sync::Arc;

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
pub(super) fn spawn_crl_listener(pool: PgPool, rebuild_notify: watch::Sender<CrlWatchValue>) {
    tokio::spawn(async move {
        loop {
            let mut listener = match sqlx::postgres::PgListener::connect_with(&pool).await {
                Ok(l) => l,
                Err(e) => {
                    error!("crl listener connect failed: {}", e);
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
            };
            if let Err(e) = listener.listen("crl_changed").await {
                error!("crl listener listen failed: {}", e);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
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
