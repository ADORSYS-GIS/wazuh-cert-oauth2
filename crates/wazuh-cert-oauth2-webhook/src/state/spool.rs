use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::Rng;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};
use wazuh_cert_oauth2_model::models::errors::AppResult;
use wazuh_cert_oauth2_model::models::revoke_request::RevokeRequest;

use super::ProxyState;

#[derive(Serialize, Deserialize)]
struct SpoolItem {
    req: RevokeRequest,
}

/// Remove queued revoke requests targeting the given subject.
/// Returns the number of files removed.
#[tracing::instrument(skip(state))]
pub async fn cancel_pending_revokes_for_subject(
    state: &ProxyState,
    subject: &str,
) -> AppResult<usize> {
    let mut removed: usize = 0;
    let mut dir = match tokio::fs::read_dir(&state.spool_dir).await {
        Ok(d) => d,
        Err(e) => {
            warn!("spool read_dir failed: {}", e);
            return Ok(0);
        }
    };
    while let Some(entry) = dir.next_entry().await? {
        let path = entry.path();
        if !is_json(&path) {
            continue;
        }
        match tokio::fs::read(&path).await {
            Ok(bytes) => match serde_json::from_slice::<SpoolItem>(&bytes) {
                Ok(item) => {
                    if item.req.subject.as_deref() == Some(subject) {
                        debug!(
                            "canceling pending revoke for {} in {}",
                            subject,
                            path.display()
                        );
                        match tokio::fs::remove_file(&path).await {
                            Ok(()) => {
                                removed += 1;
                            }
                            Err(e) => warn!("failed to remove {}: {}", path.display(), e),
                        }
                    }
                }
                Err(e) => {
                    // Leave invalid files to the regular processor to clean up
                    warn!("invalid spool item {}; skipping: {}", path.display(), e);
                }
            },
            Err(e) => warn!("failed to read {}: {}", path.display(), e),
        }
    }
    Ok(removed)
}

#[tracing::instrument(skip(state, req))]
pub async fn queue_revoke_to_spool_dir(state: &ProxyState, req: RevokeRequest) -> AppResult<()> {
    let item = SpoolItem { req };
    let data = serde_json::to_vec(&item)?;
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let mut buf = [0u8; 8];
    rand::rng().fill(&mut buf);
    let mut rid = String::with_capacity(buf.len() * 2);
    for b in buf {
        rid.push_str(&format!("{:02x}", b));
    }
    let filename = format!("revoke-{}-{}.json", ms, rid);
    let path = state.spool_dir.join(&filename);
    let tmp = state.spool_dir.join(format!("{}.tmp", filename));
    tokio::fs::write(&tmp, data).await?;
    tokio::fs::rename(&tmp, &path).await?;
    Ok(())
}

#[tracing::instrument(skip(state))]
pub async fn spawn_spool_processor(state: ProxyState) -> AppResult<()> {
    info!(
        "spool processor running; dir={} interval={:?}",
        state.spool_dir.display(),
        state.spool_interval
    );
    loop {
        if let Err(e) = process_once(&state).await {
            error!("error in spool cycle: {}", e);
        }
        tokio::time::sleep(state.spool_interval).await;
    }
}

#[tracing::instrument(skip(state))]
async fn process_once(state: &ProxyState) -> AppResult<()> {
    let mut dir = match tokio::fs::read_dir(&state.spool_dir).await {
        Ok(d) => d,
        Err(e) => {
            warn!("spool read_dir failed: {}", e);
            return Ok(());
        }
    };
    while let Some(entry) = dir.next_entry().await? {
        let path = entry.path();
        if !is_json(&path) {
            continue;
        }
        match tokio::fs::read(&path).await {
            Ok(bytes) => match serde_json::from_slice::<SpoolItem>(&bytes) {
                Ok(item) => {
                    debug!("processing spool file: {}", path.display());
                    match state.forward_revoke_with_retry(item.req).await {
                        Ok(()) => {
                            debug!("forwarded; removing {}", path.display());
                            let _ = tokio::fs::remove_file(&path).await;
                        }
                        Err(e) => warn!("still failing for {}: {}", path.display(), e),
                    }
                }
                Err(e) => {
                    warn!("invalid spool item {}; deleting: {}", path.display(), e);
                    let _ = tokio::fs::remove_file(&path).await;
                }
            },
            Err(e) => warn!("failed to read {}: {}", path.display(), e),
        }
    }
    Ok(())
}

fn is_json(p: &Path) -> bool {
    p.extension().and_then(|s| s.to_str()).unwrap_or("") == "json"
}
