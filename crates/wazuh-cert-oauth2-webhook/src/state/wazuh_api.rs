use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tracing::{debug, error, info, warn};
use wazuh_cert_oauth2_model::models::errors::{AppError, AppResult};
use wazuh_cert_oauth2_model::services::wazuh::{ArOutcome, WazuhClient};

use crate::state::spool::{ArPendingRequest, EvictRequest};

#[derive(Clone)]
pub struct WazuhApiClient {
    pub(crate) client: WazuhClient,
    pub(crate) ar_command_unix: String,
    pub(crate) ar_command_windows: String,
    pub(crate) grace_seconds: u64,
    pub(crate) ar_spool_ttl_seconds: u64,
}

impl WazuhApiClient {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        manager_url: String,
        user: Option<String>,
        password: Option<String>,
        static_token: Option<String>,
        ar_command_unix: String,
        ar_command_windows: String,
        grace_seconds: u64,
        ar_spool_ttl_seconds: u64,
    ) -> Self {
        Self {
            client: WazuhClient::new(manager_url, user, password, static_token),
            ar_command_unix,
            ar_command_windows,
            grace_seconds,
            ar_spool_ttl_seconds,
        }
    }

    /// Send an active-response command to the agent.
    #[tracing::instrument(skip(self), fields(agent_id = %agent_id, command = %command))]
    async fn send_active_response(&self, agent_id: &str, command: &str) -> AppResult<ArOutcome> {
        self.client
            .send_active_response_raw(agent_id, command)
            .await
    }

    /// Run the eviction pipeline for a given EvictRequest.
    #[tracing::instrument(skip(self, req), fields(agent_name = %req.wazuh_agent_name.as_deref().unwrap_or(""), subject = %req.subject))]
    pub async fn run_eviction(&self, req: &EvictRequest) -> AppResult<Option<ArPendingRequest>> {
        // Step 1: resolve agent
        let agent = match self
            .client
            .find_agent(req.wazuh_agent_name.as_deref(), &req.subject)
            .await?
        {
            Some(a) => a,
            None => {
                info!(
                    agent_name = ?req.wazuh_agent_name,
                    subject = %req.subject,
                    "No Wazuh agent found; skipping eviction"
                );
                return Ok(None);
            }
        };
        let agent_id = agent.id;
        let platform = agent
            .os
            .ok_or_else(|| {
                error!(
                    subject = %req.subject,
                    agent_id = %agent_id,
                    "Wazuh agent has no OS information"
                );
                AppError::UpstreamError("Wazuh agent has no OS information".to_string())
            })?
            .platform
            .to_lowercase();
        debug!(subject = %req.subject, agent_id = %agent_id, platform = %platform, "Resolved Wazuh agent");

        let is_auto_rotate = req.reason.to_ascii_lowercase().starts_with("auto-rotate");
        let mut ar_pending = None;

        // Step 2: active response
        if !is_auto_rotate {
            let command = if platform.contains("windows") {
                &self.ar_command_windows
            } else {
                &self.ar_command_unix
            };

            match self.send_active_response(&agent_id, command).await? {
                ArOutcome::Sent => {
                    // Step 3: grace period
                    let grace = Duration::from_secs(self.grace_seconds);
                    debug!(
                        subject = %req.subject,
                        grace_seconds = self.grace_seconds,
                        "Waiting grace period before agent deletion"
                    );
                    tokio::time::sleep(grace).await;
                }
                ArOutcome::AgentOffline => {
                    warn!(
                        subject = %req.subject,
                        agent_id = %agent_id,
                        "Wazuh agent is offline; spooling AR for retry and delaying deletion"
                    );
                    ar_pending = Some(ArPendingRequest {
                        agent_id: agent_id.clone(),
                        subject: req.subject.clone(),
                        command: command.clone(),
                        created_at_unix: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                    });
                    // IMPORTANT: Return early to avoid deleting the agent yet
                    return Ok(ar_pending);
                }
                ArOutcome::AgentGone => {
                    info!(
                        subject = %req.subject,
                        agent_id = %agent_id,
                        "Wazuh agent not found or already deleted; proceeding to clean up"
                    );
                }
            }

            // Step 4: actual deletion
            info!(
                subject = %req.subject,
                agent_id = %agent_id,
                "Deleting Wazuh agent from manager"
            );
            self.client
                .execute_delete_agent(&agent_id, &req.subject)
                .await?;
        } else {
            info!(
                subject = %req.subject,
                "Skipping active response for auto-rotate reason"
            );
        }

        // Step 4: delete agent
        self.client
            .execute_delete_agent(&agent_id, &req.subject)
            .await?;

        info!(
            subject = %req.subject,
            agent_id = %agent_id,
            "Eviction complete"
        );
        Ok(ar_pending)
    }

    /// Try to deliver a pending active-response command.
    #[tracing::instrument(skip(self, req), fields(agent_id = %req.agent_id, subject = %req.subject))]
    pub async fn run_ar_pending(&self, req: &ArPendingRequest) -> AppResult<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let age_secs = now.saturating_sub(req.created_at_unix);

        if age_secs > self.ar_spool_ttl_seconds {
            warn!(
                agent_id = %req.agent_id,
                subject = %req.subject,
                age_hours = age_secs / 3600,
                ttl_hours = self.ar_spool_ttl_seconds / 3600,
                "AR spool expired; forcing agent deletion"
            );
            // Force deletion even though AR command wasn't delivered
            self.client
                .execute_delete_agent(&req.agent_id, &req.subject)
                .await?;
            return Ok(());
        }

        match self
            .send_active_response(&req.agent_id, &req.command)
            .await?
        {
            ArOutcome::Sent => {
                info!(
                    agent_id = %req.agent_id,
                    subject = %req.subject,
                    "Spool retry: AR delivered successfully. Proceeding with agent deletion."
                );
                // Trigger the deletion now that AR succeeded
                self.client
                    .execute_delete_agent(&req.agent_id, &req.subject)
                    .await?;
                Ok(())
            }
            ArOutcome::AgentOffline => {
                // Return error to keep the spool item alive for next retry
                Err(AppError::UpstreamError(format!(
                    "Agent {} still offline (spooled {}h ago)",
                    req.agent_id,
                    age_secs / 3600
                )))
            }
            ArOutcome::AgentGone => {
                // Agent no longer exists (likely deleted manually), prune the spool
                info!(
                    agent_id = %req.agent_id,
                    subject = %req.subject,
                    "Agent no longer exists in Wazuh; pruning stale AR spool"
                );
                Ok(())
            }
        }
    }
}
