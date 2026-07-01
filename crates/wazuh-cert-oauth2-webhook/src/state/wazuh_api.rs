use tracing::info;
use wazuh_cert_oauth2_model::models::errors::AppResult;
use wazuh_cert_oauth2_model::services::wazuh::WazuhClient;

use crate::state::spool::EvictRequest;

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
    ) -> Self {
        Self {
            client: WazuhClient::new(manager_url, user, password, static_token),
            grace_seconds,
        }
    }

    /// Run the eviction pipeline for a given EvictRequest.
    /// Resolves the agent by name, waits the grace period, then deletes the agent.
    #[tracing::instrument(skip(self, req), fields(agent_name = %req.wazuh_agent_name.as_deref().unwrap_or(""), subject = %req.subject))]
    pub async fn run_eviction(&self, req: &EvictRequest) -> AppResult<()> {
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
                return Ok(());
            }
        };
        let agent_id = agent.id;

        let is_auto_rotate = req.reason.to_ascii_lowercase().starts_with("auto-rotate");

        if !is_auto_rotate {
            // Step 2: grace period before deletion
            let grace = std::time::Duration::from_secs(self.grace_seconds);
            info!(
                subject = %req.subject,
                agent_id = %agent_id,
                grace_seconds = self.grace_seconds,
                "Waiting grace period before agent deletion"
            );
            tokio::time::sleep(grace).await;
        } else {
            info!(
                subject = %req.subject,
                "Skipping grace period for auto-rotate reason"
            );
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
        Ok(())
    }
}
