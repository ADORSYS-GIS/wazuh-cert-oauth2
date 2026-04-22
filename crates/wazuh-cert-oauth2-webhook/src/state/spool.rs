use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::TryRng;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};
use unwrap_infallible::UnwrapInfallible;
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
    rand::rng().try_fill_bytes(&mut buf).unwrap_infallible();
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

#[cfg(test)]
mod tests {
    use super::{SpoolItem, cancel_pending_revokes_for_subject, queue_revoke_to_spool_dir};
    use crate::state::ProxyState;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::fs;
    use wazuh_cert_oauth2_model::models::revoke_request::RevokeRequest;
    use wazuh_cert_oauth2_model::services::http_client::HttpClient;

    fn unique_spool_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        std::env::temp_dir().join(format!("wazuh-webhook-spool-test-{}", nanos))
    }

    fn build_state(spool_dir: PathBuf) -> ProxyState {
        ProxyState::new(
            "https://server.example".to_string(),
            spool_dir,
            HttpClient::new_with_defaults().expect("http client"),
            2,
            Duration::from_millis(5),
            Duration::from_millis(20),
            Duration::from_secs(1),
            None,
            None,
            None,
            None,
            None,
            None,
            "revoke".to_string(),
            None,
            None,
            None,
            None,
        )
        .expect("state should build")
    }

    async fn json_files(dir: &PathBuf) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut reader = fs::read_dir(dir).await.expect("dir should be readable");
        while let Some(entry) = reader.next_entry().await.expect("next entry should work") {
            let p = entry.path();
            if p.extension().and_then(|x| x.to_str()) == Some("json") {
                out.push(p);
            }
        }
        out
    }

    #[tokio::test]
    async fn queue_revoke_writes_spool_file() {
        let spool_dir = unique_spool_dir();
        let state = build_state(spool_dir.clone());

        queue_revoke_to_spool_dir(
            &state,
            RevokeRequest {
                serial_hex: None,
                subject: Some("user-1".to_string()),
                reason: Some("reason".to_string()),
            },
        )
        .await
        .expect("queue should succeed");

        let files = json_files(&spool_dir).await;
        assert_eq!(files.len(), 1);

        let _ = fs::remove_dir_all(&spool_dir).await;
    }

    #[tokio::test]
    async fn cancel_pending_revokes_removes_only_matching_subject() {
        let spool_dir = unique_spool_dir();
        let state = build_state(spool_dir.clone());

        queue_revoke_to_spool_dir(
            &state,
            RevokeRequest {
                serial_hex: None,
                subject: Some("user-a".to_string()),
                reason: Some("reason".to_string()),
            },
        )
        .await
        .expect("queue should succeed");
        queue_revoke_to_spool_dir(
            &state,
            RevokeRequest {
                serial_hex: None,
                subject: Some("user-b".to_string()),
                reason: Some("reason".to_string()),
            },
        )
        .await
        .expect("queue should succeed");

        let removed = cancel_pending_revokes_for_subject(&state, "user-a")
            .await
            .expect("cancel should succeed");
        assert_eq!(removed, 1);

        let files = json_files(&spool_dir).await;
        assert_eq!(files.len(), 1);
        let bytes = fs::read(&files[0]).await.expect("remaining file should be readable");
        let item: SpoolItem = serde_json::from_slice(&bytes).expect("json should parse");
        assert_eq!(item.req.subject.as_deref(), Some("user-b"));

        let _ = fs::remove_dir_all(&spool_dir).await;
    }
}
