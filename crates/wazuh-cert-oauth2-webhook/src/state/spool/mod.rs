use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{error, info, warn};
use wazuh_cert_oauth2_model::models::errors::AppResult;
use wazuh_cert_oauth2_model::models::revoke_request::RevokeRequest;

use super::ProxyState;
use super::wazuh_api::EvictionOutcome;

mod dir;
mod postgres;

pub use dir::DirSpoolStore;
pub use postgres::PostgresSpoolStore;

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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) enum SpoolItem {
    RevokeRequest { req: RevokeRequest },
    GitHubTicket { ticket: GitHubTicket },
    EvictRequest { req: EvictRequest },
}

/// Postgres ENUM for the `spool_item.item_type` column.
#[derive(sqlx::Type, Debug, Clone, Copy)]
#[sqlx(type_name = "spool_item_type", rename_all = "snake_case")]
pub enum SpoolItemType {
    Revoke,
    GithubTicket,
    Evict,
}

impl SpoolItem {
    fn item_type(&self) -> SpoolItemType {
        match self {
            SpoolItem::RevokeRequest { .. } => SpoolItemType::Revoke,
            SpoolItem::GitHubTicket { .. } => SpoolItemType::GithubTicket,
            SpoolItem::EvictRequest { .. } => SpoolItemType::Evict,
        }
    }
}

impl std::fmt::Display for SpoolItemType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SpoolItemType::Revoke => "revoke",
            SpoolItemType::GithubTicket => "github_ticket",
            SpoolItemType::Evict => "evict",
        };
        write!(f, "{}", s)
    }
}

/// Selects the spool storage backend.
#[derive(Clone)]
pub enum SpoolBackend {
    /// On-disk JSON directory (local-dev / tests / fallback).
    Dir {
        dir: std::path::PathBuf,
        dead_letter_dir: std::path::PathBuf,
    },
    /// PostgreSQL `spool_item` table (system of record for multi-replica).
    Postgres(PgPool),
}

/// A spool item claimed for processing.
pub struct ClaimedItem {
    pub id: String,
    pub item: SpoolItem,
    pub triggered_at_unix: u64,
}

/// Storage backend for the reliable-delivery spool.
#[async_trait]
pub trait SpoolStore: Send + Sync {
    async fn enqueue(
        &self,
        item: SpoolItem,
        triggered_at_unix: u64,
        delete_after_unix: Option<u64>,
    ) -> AppResult<()>;

    /// Return the items to process this cycle. The processor iterates over
    /// this snapshot once per cycle (then sleeps), so a persistently failing
    /// item is retried next cycle rather than busy-looping. For Postgres this
    /// atomically claims the items (sets `state = 'in_progress'` via
    /// `FOR UPDATE SKIP LOCKED`) so concurrent replicas don't double-process.
    async fn list_pending(&self) -> AppResult<Vec<ClaimedItem>>;

    async fn mark_done(&self, id: &str) -> AppResult<()>;
    async fn mark_dead_letter(&self, id: &str, error: &str) -> AppResult<()>;
    async fn update_item(
        &self,
        id: &str,
        item: &SpoolItem,
        delete_after_unix: Option<u64>,
    ) -> AppResult<()>;

    /// Return a failed item to pending so it is retried on the next cycle
    /// (respecting the spool interval). For the directory backend this is a
    /// no-op (items stay on disk and are re-listed next cycle); for Postgres
    /// it sets `state = 'pending'` so the item isn't stuck in `in_progress`
    /// until the crash-recovery reclaim.
    async fn retry(&self, id: &str) -> AppResult<()>;
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Queue entry points
// ---------------------------------------------------------------------------

pub async fn queue_revoke(state: &ProxyState, req: RevokeRequest) -> AppResult<()> {
    state
        .spool
        .enqueue(SpoolItem::RevokeRequest { req }, now_unix(), None)
        .await
}

pub async fn queue_github_ticket(state: &ProxyState, ticket: GitHubTicket) -> AppResult<()> {
    state
        .spool
        .enqueue(SpoolItem::GitHubTicket { ticket }, now_unix(), None)
        .await
}

pub async fn queue_evict(state: &ProxyState, req: EvictRequest) -> AppResult<()> {
    let delete_after = req.delete_after_unix;
    state
        .spool
        .enqueue(SpoolItem::EvictRequest { req }, now_unix(), delete_after)
        .await
}

// ---------------------------------------------------------------------------
// Processor
// ---------------------------------------------------------------------------

#[tracing::instrument(skip(state))]
pub async fn spawn_spool_processor(state: ProxyState) -> AppResult<()> {
    info!(
        "spool processor running; interval={:?}",
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
    // Process a snapshot of items once per cycle, then yield to the interval
    // sleep. Persistently failing items are retried on the next cycle.
    for claimed in state.spool.list_pending().await? {
        let id = claimed.id;
        let triggered_at = claimed.triggered_at_unix;
        match claimed.item {
            SpoolItem::RevokeRequest { req } => match state.forward_revoke_with_retry(req).await {
                Ok(()) => state.spool.mark_done(&id).await?,
                Err(e) => {
                    warn!("still failing for {}: {}", id, e);
                    state.spool.retry(&id).await?;
                }
            },
            SpoolItem::GitHubTicket { ticket } => {
                match state.forward_github_ticket_with_retry(ticket).await {
                    Ok(()) => state.spool.mark_done(&id).await?,
                    Err(e) => {
                        warn!("still failing for {}: {}", id, e);
                        state.spool.retry(&id).await?;
                    }
                }
            }
            SpoolItem::EvictRequest { req } => {
                // Not-yet-due evictions are filtered out by list_pending, so we
                // only reach here when the item is due.
                let req_subject = req.subject.clone();
                match state.run_eviction_from_state(req).await {
                    Ok(EvictionOutcome::Done) => state.spool.mark_done(&id).await?,
                    Ok(EvictionOutcome::Pending(updated_req)) => {
                        let updated = SpoolItem::EvictRequest {
                            req: updated_req.clone(),
                        };
                        state
                            .spool
                            .update_item(&id, &updated, updated_req.delete_after_unix)
                            .await?;
                    }
                    Err(e) => {
                        let now = now_unix();
                        let age = now.saturating_sub(triggered_at);
                        let ttl = state.spool_evict_ttl.as_secs();
                        if age > ttl {
                            error!(
                                subject = %req_subject,
                                id = %id,
                                age_secs = age,
                                ttl_secs = ttl,
                                error = %e,
                                "Eviction spool item exceeded TTL; dead-lettering",
                            );
                            state.spool.mark_dead_letter(&id, &e.to_string()).await?;
                        } else {
                            warn!(
                                "eviction still failing for {} (age {}s, TTL {}s): {}",
                                id, age, ttl, e
                            );
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn is_json(p: &Path) -> bool {
    p.extension().and_then(|s| s.to_str()).unwrap_or("") == "json"
}

#[cfg(test)]
mod tests {
    use super::{EvictRequest, SpoolBackend, SpoolItem, process_once, queue_evict, queue_revoke};
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

    fn unique_dlq_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        std::env::temp_dir().join(format!("wazuh-webhook-dlq-test-{}", nanos))
    }

    fn build_state(spool_dir: PathBuf) -> ProxyState {
        build_state_with(
            spool_dir,
            None,
            unique_dlq_dir(),
            Duration::from_secs(86400),
        )
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
            SpoolBackend::Dir {
                dir: spool_dir,
                dead_letter_dir: dlq_dir,
            },
            HttpClient::new_with_defaults().expect("http client"),
            2,
            Duration::from_millis(5),
            Duration::from_millis(20),
            Duration::from_secs(1),
            ttl,
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

        queue_revoke(
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

        queue_evict(&state, req.clone())
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
        queue_evict(&state, req)
            .await
            .expect("queue should succeed");

        // Verify the file is in the spool dir before processing.
        let spool_files = json_files(&spool_dir).await;
        assert_eq!(spool_files.len(), 1);

        // Process the spool — eviction fails (no credentials) and the item
        // is past TTL, so it should be moved to the dead-letter directory.
        process_once(&state)
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
        queue_evict(&state, req)
            .await
            .expect("queue should succeed");

        process_once(&state)
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
            SpoolBackend::Dir {
                dir: spool_dir.clone(),
                dead_letter_dir: spool_dir.clone(), // same as spool_dir — should fail
            },
            HttpClient::new_with_defaults().expect("http client"),
            2,
            Duration::from_millis(5),
            Duration::from_millis(20),
            Duration::from_secs(1),
            Duration::from_secs(86400),
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
