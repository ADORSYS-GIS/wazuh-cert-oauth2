use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;
use wazuh_cert_oauth2_model::models::errors::AppResult;
use wazuh_cert_oauth2_model::services::wazuh::WazuhClient;

use crate::state::spool::EvictRequest;

/// Outcome of an eviction attempt — used by the spool processor to decide
/// whether to remove, re-write, or skip the spool file.
#[derive(Debug)]
pub enum EvictionOutcome {
    /// Agent deleted (or not found / no Wazuh configured) — remove spool file.
    Done,
    /// Grace period started — re-write spool file with updated `agent_id` and
    /// `delete_after_unix`. The file is NOT removed.
    Pending(EvictRequest),
}

#[derive(Clone)]
pub struct WazuhApiClient {
    pub(crate) client: WazuhClient,
    pub(crate) grace_seconds: u64,
}

impl WazuhApiClient {
    pub fn new(
        manager_url: String,
        user: Option<String>,
        password: Option<String>,
        static_token: Option<String>,
        grace_seconds: u64,
        tls_verify: bool,
        ca_bundle: Option<PathBuf>,
    ) -> Self {
        Self {
            client: WazuhClient::with_tls_options(
                manager_url,
                user,
                password,
                static_token,
                tls_verify,
                ca_bundle,
            ),
            grace_seconds,
        }
    }

    /// Run the eviction pipeline for a given EvictRequest.
    ///
    /// Instead of blocking the spool processor with `tokio::sleep(grace)`,
    /// this method sets `delete_after_unix` on the request and returns
    /// `EvictionOutcome::Pending`. The spool processor re-writes the file
    /// and skips it until the grace period elapses, allowing other spool
    /// items to be processed in the meantime.
    #[tracing::instrument(skip(self, req), fields(agent_name = %req.wazuh_agent_name.as_deref().unwrap_or(""), subject = %req.subject))]
    pub async fn run_eviction(&self, req: &EvictRequest) -> AppResult<EvictionOutcome> {
        let is_auto_rotate = req.reason.to_ascii_lowercase().starts_with("auto-rotate");

        // Step 1: resolve agent (skip if already resolved from a previous cycle)
        let agent_id = match &req.agent_id {
            Some(id) => id.clone(),
            None => match self
                .client
                .find_agent(req.wazuh_agent_name.as_deref(), &req.subject)
                .await?
            {
                Some(a) => a.id,
                None => {
                    info!(
                        agent_name = ?req.wazuh_agent_name,
                        subject = %req.subject,
                        "No Wazuh agent found; skipping eviction"
                    );
                    return Ok(EvictionOutcome::Done);
                }
            },
        };

        // Step 2: handle grace period
        if !is_auto_rotate && req.delete_after_unix.is_none() {
            // First time processing — set the grace deadline and return Pending.
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let delete_after = now + self.grace_seconds;
            info!(
                subject = %req.subject,
                agent_id = %agent_id,
                grace_seconds = self.grace_seconds,
                "Grace period started; eviction will proceed after {} (unix {})",
                delete_after, delete_after
            );
            let mut updated = req.clone();
            updated.agent_id = Some(agent_id);
            updated.delete_after_unix = Some(delete_after);
            return Ok(EvictionOutcome::Pending(updated));
        }

        // Step 3: delete agent
        info!(
            subject = %req.subject,
            agent_id = %agent_id,
            "Deleting Wazuh agent from manager"
        );
        self.client
            .execute_delete_agent(&agent_id, &req.subject)
            .await?;

        info!(
            subject = %req.subject,
            agent_id = %agent_id,
            "Eviction complete"
        );
        Ok(EvictionOutcome::Done)
    }
}
