use std::time::Duration;

use tracing::{debug, info};
use wazuh_cert_oauth2_model::models::errors::{AppError, AppResult};
use wazuh_cert_oauth2_model::services::wazuh::WazuhClient;

use crate::state::spool::EvictRequest;

#[derive(Clone)]
pub struct WazuhApiClient {
    pub(crate) client: WazuhClient,
    pub(crate) ar_command: String,
    pub(crate) grace_seconds: u64,
}

impl WazuhApiClient {
    pub fn new(
        manager_url: String,
        user: Option<String>,
        password: Option<String>,
        static_token: Option<String>,
        ar_command: String,
        grace_seconds: u64,
    ) -> Self {
        Self {
            client: WazuhClient::new(manager_url, user, password, static_token),
            ar_command,
            grace_seconds,
        }
    }

    /// Send an active-response command to the agent.
    #[tracing::instrument(skip(self), fields(agent_id = %agent_id))]
    async fn send_active_response(&self, agent_id: &str) -> AppResult<()> {
        let url = format!(
            "{}/active-response?agents_list={}",
            self.client.manager_url.trim_end_matches('/'),
            agent_id
        );
        let payload = serde_json::json!({
            "command": format!("!{}", self.ar_command),
            "arguments": []
        });
        debug!(agent_id, "active-response payload: {:?}", payload);

        let http_client = self.client.get_http_client().clone();
        
        let resp = self
            .client
            .with_retry(|token| {
                let url = url.clone();
                let payload = payload.clone();
                let http = http_client.clone();
                async move { Ok(http.put(&url).bearer_auth(token).json(&payload)) }
            })
            .await?;

        if !resp.status().is_success() {
            return Err(AppError::UpstreamError(format!(
                "PUT /active-response returned {}",
                resp.status()
            )));
        }
        info!(agent_id, "active-response delete-cert sent");
        Ok(())
    }

    /// Run the eviction pipeline for a given EvictRequest.
    #[tracing::instrument(skip(self, req), fields(agent_name = %req.wazuh_agent_name.as_deref().unwrap_or(""), subject = %req.subject))]
    pub async fn run_eviction(&self, req: &EvictRequest) -> AppResult<()> {
        // Step 1: resolve agent
        let agent_id = match self
            .client
            .find_agent_id(req.wazuh_agent_name.as_deref(), &req.subject)
            .await?
        {
            Some(id) => id,
            None => {
                info!(
                    agent_name = ?req.wazuh_agent_name,
                    subject = %req.subject,
                    "No Wazuh agent found; skipping eviction"
                );
                return Ok(());
            }
        };
        debug!(subject = %req.subject, agent_id = %agent_id, "Resolved Wazuh agent");

        let is_auto_rotate = req.reason.to_ascii_lowercase().starts_with("auto-rotate");

        // Step 2: active response
        if !is_auto_rotate {
            self.send_active_response(&agent_id).await?;
        } else {
            info!(subject = %req.subject, "Skipping active response for auto-rotate reason");
        }

        // Step 3: grace period
        if !is_auto_rotate {
            let grace = Duration::from_secs(self.grace_seconds);
            debug!(
                subject = %req.subject,
                grace_seconds = self.grace_seconds,
                "Waiting grace period before agent deletion"
            );
            tokio::time::sleep(grace).await;
        } else {
            debug!(subject = %req.subject, "Skipping grace period for auto-rotate reason");
        }

        // Step 4: delete agent
        self.client.execute_delete_agent(&agent_id, &req.subject).await?;

        info!(
            subject = %req.subject,
            agent_id = %agent_id,
            "Eviction complete"
        );
        Ok(())
    }
}
