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
    // Ensure the dead-letter directory exists.
    let dlq_dir = state.spool_dead_letter_dir.clone();
    if let Err(e) = tokio::fs::create_dir_all(&dlq_dir).await {
        warn!(
            "failed to create dead-letter dir {}: {}",
            dlq_dir.display(),
            e
        );
    }
    loop {
        if let Err(e) = process_once(&state, &dlq_dir).await {
            error!("error in spool cycle: {}", e);
        }
        tokio::time::sleep(state.spool_interval).await;
    }
}

#[tracing::instrument(skip(state, dlq_dir))]
async fn process_once(state: &ProxyState, dlq_dir: &Path) -> AppResult<()> {
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
                                            } else if let Err(e) =
                                                tokio::fs::rename(&tmp, &path).await
                                            {
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
                                    let ttl = state.spool_evict_ttl.as_secs();
                                    if age > ttl {
                                        let dlq_path =
                                            dlq_dir.join(path.file_name().unwrap_or_default());
                                        error!(
                                            subject = %req_subject,
                                            path = %path.display(),
                                            dead_letter_path = %dlq_path.display(),
                                            age_secs = age,
                                            ttl_secs = ttl,
                                            error = %e,
                                            "Eviction spool item exceeded TTL; moving to dead-letter directory",
                                        );
                                        if let Err(rename_err) =
                                            tokio::fs::rename(&path, &dlq_path).await
                                        {
                                            error!(
                                                subject = %req_subject,
                                                src = %path.display(),
                                                dst = %dlq_path.display(),
                                                error = %rename_err,
                                                "Failed to move expired spool item to dead-letter directory; \
                                                 leaving in spool for next cycle",
                                            );
                                        }
                                    } else {
                                        warn!(
                                            "eviction still failing for {} (age {}s, TTL {}s): {}",
                                            path.display(),
                                            age,
                                            ttl,
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
    use super::{
        EvictRequest, SpoolItem, process_once, queue_evict_to_spool_dir, queue_revoke_to_spool_dir,
    };
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
        build_state_with(
            spool_dir,
            None,
            unique_dlq_dir(),
            Duration::from_secs(86400),
        )
    }

    fn unique_dlq_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        std::env::temp_dir().join(format!("wazuh-webhook-dlq-test-{}", nanos))
    }

    /// Like `build_state` but allows setting `wazuh_manager_url` so that
    /// `run_eviction_from_state` enters the `Some(client)` branch. With no
    /// credentials configured the Wazuh client fails fast with an `Err`.
    /// `ttl` controls the dead-letter TTL used by the spool processor.
    fn build_state_with(
        spool_dir: PathBuf,
        wazuh_manager_url: Option<String>,
        dlq_dir: PathBuf,
        ttl: Duration,
    ) -> ProxyState {
        ProxyState::new(
            "https://server.example".to_string(),
            spool_dir,
            HttpClient::new_with_defaults().expect("http client"),
            2,
            Duration::from_millis(5),
            Duration::from_millis(20),
            Duration::from_secs(1),
            ttl,
            dlq_dir,
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
            wazuh_manager_url,
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

    #[tokio::test]
    async fn expired_evict_item_moved_to_dead_letter_dir() {
        let spool_dir = unique_spool_dir();
        let dlq_dir = unique_dlq_dir();
        // Configure a Wazuh manager URL but no credentials, so run_eviction
        // fails fast with Err("No Wazuh API credentials configured").
        let state = build_state_with(
            spool_dir.clone(),
            Some("http://127.0.0.1:1".to_string()),
            dlq_dir.clone(),
            Duration::from_secs(86400),
        );

        // Create the dead-letter directory (normally done by spawn_spool_processor).
        fs::create_dir_all(&dlq_dir).await.expect("create dlq dir");

        // Write an EvictRequest that is already past the 24h TTL.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let req = EvictRequest {
            subject: "user-expired".to_string(),
            wazuh_agent_name: Some("agent-1".to_string()),
            reason: "test-revocation".to_string(),
            triggered_at_unix: now - 25 * 60 * 60, // 25h ago — past 24h TTL
            agent_id: None,
            delete_after_unix: None,
        };
        queue_evict_to_spool_dir(&state, req)
            .await
            .expect("queue should succeed");

        // Verify the file is in the spool dir before processing.
        let spool_files = json_files(&spool_dir).await;
        assert_eq!(spool_files.len(), 1);

        // Process the spool — eviction fails (no credentials) and the item
        // is past TTL, so it should be moved to the dead-letter directory.
        process_once(&state, &dlq_dir)
            .await
            .expect("process_once should succeed");

        // The spool dir should now be empty (file moved out).
        let spool_files_after = json_files(&spool_dir).await;
        assert!(
            spool_files_after.is_empty(),
            "spool dir should be empty after dead-lettering, found: {spool_files_after:?}",
        );

        // The dead-letter dir should contain exactly one file.
        let dlq_files = json_files(&dlq_dir).await;
        assert_eq!(
            dlq_files.len(),
            1,
            "dead-letter dir should contain one file"
        );

        // The file should be readable and contain the EvictRequest.
        let bytes = fs::read(&dlq_files[0])
            .await
            .expect("dlq file should be readable");
        let item: SpoolItem = serde_json::from_slice(&bytes).expect("json should parse");
        match item {
            SpoolItem::EvictRequest { req } => {
                assert_eq!(req.subject, "user-expired");
            }
            _ => panic!("Expected EvictRequest variant"),
        }

        // Clean up both the spool dir and the DLQ dir.
        let _ = fs::remove_dir_all(&spool_dir).await;
        let _ = fs::remove_dir_all(&dlq_dir).await;
    }

    #[tokio::test]
    async fn custom_ttl_is_respected() {
        let spool_dir = unique_spool_dir();
        let dlq_dir = unique_dlq_dir();
        // Use a 60s TTL — an item 90s old should be dead-lettered.
        let state = build_state_with(
            spool_dir.clone(),
            Some("http://127.0.0.1:1".to_string()),
            dlq_dir.clone(),
            Duration::from_secs(60),
        );
        fs::create_dir_all(&dlq_dir).await.expect("create dlq dir");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let req = EvictRequest {
            subject: "user-custom-ttl".to_string(),
            wazuh_agent_name: Some("agent-1".to_string()),
            reason: "test-revocation".to_string(),
            triggered_at_unix: now - 90, // 90s ago — past 60s TTL
            agent_id: None,
            delete_after_unix: None,
        };
        queue_evict_to_spool_dir(&state, req)
            .await
            .expect("queue should succeed");

        process_once(&state, &dlq_dir)
            .await
            .expect("process_once should succeed");

        // Item should be gone from spool and present in DLQ.
        assert!(json_files(&spool_dir).await.is_empty());
        let dlq_files = json_files(&dlq_dir).await;
        assert_eq!(dlq_files.len(), 1);

        let _ = fs::remove_dir_all(&spool_dir).await;
        let _ = fs::remove_dir_all(&dlq_dir).await;
    }

    #[test]
    fn builder_rejects_dlq_dir_equal_to_spool_dir() {
        let spool_dir = unique_spool_dir();
        let result = ProxyState::new(
            "https://server.example".to_string(),
            spool_dir.clone(),
            HttpClient::new_with_defaults().expect("http client"),
            2,
            Duration::from_millis(5),
            Duration::from_millis(20),
            Duration::from_secs(1),
            Duration::from_secs(86400),
            spool_dir.clone(), // same as spool_dir — should fail
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
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            30,
            false,
            None,
        );
        assert!(
            result.is_err(),
            "ProxyState::new should reject DLQ dir == spool dir",
        );
        let _ = std::fs::remove_dir_all(&spool_dir);
    }
}
