use std::time::{SystemTime, UNIX_EPOCH};

use tracing::warn;
use wazuh_cert_oauth2_model::services::http_client::HttpClient;

/// Minimal eviction payload sent to the webhook's internal endpoint.
#[derive(serde::Serialize)]
struct EvictRequest {
    subject: String,
    wazuh_agent_name: Option<String>,
    reason: String,
    triggered_at_unix: u64,
}

/// Fires eviction requests to the webhook after an auto-rotate override.
/// All fields are optional so the server starts fine without webhook config.
#[derive(Clone)]
pub struct WebhookNotifier {
    http: HttpClient,
    base_url: String,
    bearer_token: Option<String>,
}

impl WebhookNotifier {
    pub fn new(http: HttpClient, base_url: String, bearer_token: Option<String>) -> Self {
        Self {
            http,
            base_url,
            bearer_token,
        }
    }

    /// Fire-and-forget: POST an eviction request to the webhook for each old agent name.
    /// Logs a warning on failure but never propagates the error — eviction is best-effort.
    pub async fn notify_evict(&self, subject: &str, old_agent_names: Vec<String>) {
        let url = format!(
            "{}/api/internal/evict",
            self.base_url.trim_end_matches('/')
        );
        let triggered_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // One request per old agent name; typically just one.
        // If no agent names were stored (legacy enrollment), send one request with None
        // so the webhook can still attempt a subject-based lookup if it ever gains that path.
        let names: Vec<Option<String>> = if old_agent_names.is_empty() {
            vec![None]
        } else {
            old_agent_names.into_iter().map(Some).collect()
        };

        for agent_name in names {
            let req = EvictRequest {
                subject: subject.to_string(),
                wazuh_agent_name: agent_name,
                reason: "auto-rotate (one cert per user)".to_string(),
                triggered_at_unix,
            };

            let result = match &self.bearer_token {
                Some(token) => {
                    self.http
                        .client()
                        .post(&url)
                        .bearer_auth(token)
                        .json(&req)
                        .send()
                        .await
                }
                None => self.http.client().post(&url).json(&req).send().await,
            };

            match result {
                Ok(resp) if resp.status().is_success() => {}
                Ok(resp) => {
                    warn!(
                        subject,
                        status = %resp.status(),
                        "Webhook eviction notification returned non-success"
                    );
                }
                Err(e) => {
                    warn!(subject, "Failed to notify webhook of eviction: {}", e);
                }
            }
        }
    }
}
