use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::TryRng;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};
use unwrap_infallible::UnwrapInfallible;
use wazuh_cert_oauth2_model::models::errors::AppResult;
use wazuh_cert_oauth2_model::models::revoke_request::RevokeRequest;

use super::ProxyState;
use super::wazuh_api::EvictionOutcome;

/// Maximum time (in seconds) an EvictRequest stays in the spool before being
/// force-deleted as a dead-letter. Prevents unbounded retry of poison items.
const EVICT_SPOOL_TTL_SECS: u64 = 24 * 60 * 60;

/// Represents a pending GitHub ticket.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GitHubTicket {
    pub title: String,
    pub body: String,
}

/// Represents a request to evict (disconnect + delete) a Wazuh agent.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EvictRequest {
    pub subject: String,
    pub wazuh_agent_name: Option<String>,
    pub reason: String,
    pub triggered_at_unix: u64,
    /// Resolved Wazuh agent ID (set after first lookup to avoid re-querying).
    #[serde(default)]
    pub agent_id: Option<String>,
    /// Unix timestamp after which the deletion may proceed (grace period end).
    /// Set on first processing; the spool processor skips the item until due.
    #[serde(default)]
    pub delete_after_unix: Option<u64>,
}

#[derive(Serialize, Deserialize)]
enum SpoolItem {
    RevokeRequest { req: RevokeRequest },
    GitHubTicket { ticket: GitHubTicket },
    EvictRequest { req: EvictRequest },
}

#[tracing::instrument(skip(state, item))]
async fn queue_item_to_spool_dir(
    state: &ProxyState,
    item: SpoolItem,
    prefix: &str,
) -> AppResult<()> {
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
    let filename = format!("{}-{}-{}.json", prefix, ms, rid);
    let path = state.spool_dir.join(&filename);
    let tmp = state.spool_dir.join(format!("{}.tmp", filename));
    tokio::fs::write(&tmp, data).await?;
    tokio::fs::rename(&tmp, &path).await?;
    Ok(())
}

pub async fn queue_revoke_to_spool_dir(state: &ProxyState, req: RevokeRequest) -> AppResult<()> {
    queue_item_to_spool_dir(state, SpoolItem::RevokeRequest { req }, "revoke").await
}

pub async fn queue_github_ticket_to_spool_dir(
    state: &ProxyState,
    ticket: GitHubTicket,
) -> AppResult<()> {
    queue_item_to_spool_dir(state, SpoolItem::GitHubTicket { ticket }, "ticket").await
}

pub async fn queue_evict_to_spool_dir(state: &ProxyState, req: EvictRequest) -> AppResult<()> {
    queue_item_to_spool_dir(state, SpoolItem::EvictRequest { req }, "evict").await
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
                    match item {
                        SpoolItem::RevokeRequest { req } => {
                            match state.forward_revoke_with_retry(req).await {
                                Ok(()) => {
                                    debug!("successfully processed {}; removing", path.display());
                                    let _ = tokio::fs::remove_file(&path).await;
                                }
                                Err(e) => warn!("still failing for {}: {}", path.display(), e),
                            }
                        }
                        SpoolItem::GitHubTicket { ticket } => {
                            match state.forward_github_ticket_with_retry(ticket).await {
                                Ok(()) => {
                                    debug!("successfully processed {}; removing", path.display());
                                    let _ = tokio::fs::remove_file(&path).await;
                                }
                                Err(e) => warn!("still failing for {}: {}", path.display(), e),
                            }
                        }
                        SpoolItem::EvictRequest { req } => {
                            // Skip if grace period hasn't elapsed yet.
                            if let Some(delete_after) = req.delete_after_unix {
                                let now = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();
                                if now < delete_after {
                                    debug!(
                                        "eviction for {} not yet due ({}s remaining)",
                                        req.subject,
                                        delete_after - now
                                    );
                                    continue;
                                }
                            }

                            // Capture fields needed for TTL check before `req` is moved.
                            let triggered_at = req.triggered_at_unix;
                            let req_subject = req.subject.clone();

                            match state.run_eviction_from_state(req).await {
                                Ok(EvictionOutcome::Done) => {
                                    debug!("eviction complete; removing {}", path.display());
                                    let _ = tokio::fs::remove_file(&path).await;
                                }
                                Ok(EvictionOutcome::Pending(updated_req)) => {
                                    // Re-write spool file with updated agent_id and delete_after_unix.
                                    let updated = SpoolItem::EvictRequest { req: updated_req };
                                    match serde_json::to_vec(&updated) {
                                        Ok(data) => {
                                            let tmp = path.with_extension("json.tmp");
                                            if let Err(e) = tokio::fs::write(&tmp, &data).await {
                                                error!(
                                                    "failed to write temp spool file {}: {}",
                                                    tmp.display(),
                                                    e
                                                );
                                            } else if let Err(e) = tokio::fs::rename(&tmp, &path).await {
                                                error!(
                                                    "failed to rename temp spool file {} -> {}: {}",
                                                    tmp.display(),
                                                    path.display(),
                                                    e
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            error!("failed to serialize updated spool item: {}", e)
                                        }
                                    }
                                }
                                Err(e) => {
                                    let now = SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    let age = now.saturating_sub(triggered_at);
                                    if age > EVICT_SPOOL_TTL_SECS {
                                        error!(
                                            subject = %req_subject,
                                            path = %path.display(),
                                            age_secs = age,
                                            error = %e,
                                            "Eviction spool item exceeded TTL ({}s); dead-lettering (removing)",
                                            EVICT_SPOOL_TTL_SECS
                                        );
                                        let _ = tokio::fs::remove_file(&path).await;
                                    } else {
                                        warn!(
                                            "eviction still failing for {} (age {}s, TTL {}s): {}",
                                            path.display(),
                                            age,
                                            EVICT_SPOOL_TTL_SECS,
                                            e
                                        );
                                    }
                                }
                            }
                        }
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
    use super::{EvictRequest, SpoolItem, queue_evict_to_spool_dir, queue_revoke_to_spool_dir};
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
            // webhook (4)
            None,
            None,
            None,
            None,
            // github (3)
            None,
            None,
            None,
            // keycloak_admin_base_url
            None,
            // wazuh: manager_url, api_user, api_password, api_token
            None,
            None,
            None,
            None,
            // wazuh_eviction_grace_seconds
            30,
            // wazuh_api_tls_verify, wazuh_api_ca_bundle
            false,
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
    async fn queue_evict_writes_spool_file() {
        let spool_dir = unique_spool_dir();
        let state = build_state(spool_dir.clone());

        let req = EvictRequest {
            subject: "user-evict".to_string(),
            wazuh_agent_name: Some("agent-name".to_string()),
            reason: "test-revocation".to_string(),
            triggered_at_unix: 1234567890,
            agent_id: None,
            delete_after_unix: None,
        };

        queue_evict_to_spool_dir(&state, req.clone())
            .await
            .expect("queue should succeed");

        let files = json_files(&spool_dir).await;
        assert_eq!(files.len(), 1);

        let bytes = fs::read(&files[0])
            .await
            .expect("spool file should be readable");
        let item: SpoolItem = serde_json::from_slice(&bytes).expect("json should parse");
        match item {
            SpoolItem::EvictRequest { req: read_req } => {
                assert_eq!(read_req.subject, req.subject);
                assert_eq!(read_req.wazuh_agent_name, req.wazuh_agent_name);
            }
            _ => panic!("Expected EvictRequest variant"),
        }

        let _ = fs::remove_dir_all(&spool_dir).await;
    }
}
