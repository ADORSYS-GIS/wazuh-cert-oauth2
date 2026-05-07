use reqwest::Client;
use serde::Deserialize;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::models::errors::{AppError, AppResult};

#[derive(Deserialize)]
struct AuthResponse {
    data: AuthData,
}

#[derive(Deserialize)]
struct AuthData {
    token: String,
}

#[derive(Deserialize)]
struct AgentsResponse {
    data: AgentsData,
}

#[derive(Deserialize)]
struct AgentsData {
    affected_items: Vec<AgentItem>,
}

#[derive(Deserialize, Debug)]
struct AgentItem {
    id: String,
    name: String,
}

#[derive(Deserialize, Debug)]
struct ArResponse {
    data: ArData,
    #[serde(default)]
    error: u32,
}

#[derive(Deserialize, Debug, Default)]
struct ArData {
    #[serde(default)]
    total_affected_items: u32,
    #[serde(default)]
    failed_items: Vec<ArFailedItem>,
}

#[derive(Deserialize, Debug)]
struct ArFailedItem {
    error: ArFailedItemError,
}

#[derive(Deserialize, Debug)]
struct ArFailedItemError {
    code: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ArOutcome {
    Sent,
    AgentOffline,
    AgentGone,
}

#[derive(Clone)]
struct CachedToken {
    token: String,
    exp: Instant,
}

#[derive(Clone)]
pub struct WazuhClient {
    pub manager_url: String,
    user: Option<String>,
    password: Option<String>,
    static_token: Option<String>,
    token_cache: Arc<RwLock<Option<CachedToken>>>,
    http: Client,
}

impl WazuhClient {
    pub fn new(
        manager_url: String,
        user: Option<String>,
        password: Option<String>,
        static_token: Option<String>,
    ) -> Self {
        Self {
            manager_url,
            user,
            password,
            static_token,
            token_cache: Arc::new(RwLock::new(None)),
            http: Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(Duration::from_secs(30))
                .build()
                .expect("reqwest client"),
        }
    }

    async fn acquire_token(&self) -> AppResult<String> {
        if self.user.is_none() || self.password.is_none() {
            return self.static_token.clone().ok_or_else(|| {
                AppError::UpstreamError("No Wazuh API credentials configured".into())
            });
        }

        if let Some(cached) = (*self.token_cache.read().await).clone() {
            if Instant::now() < cached.exp {
                return Ok(cached.token);
            }
        }

        self.fetch_and_cache_token().await
    }

    async fn fetch_and_cache_token(&self) -> AppResult<String> {
        let url = format!(
            "{}/security/user/authenticate",
            self.manager_url.trim_end_matches('/')
        );
        let user = self.user.as_deref().unwrap_or("");
        let pass = self.password.as_deref().unwrap_or("");

        let resp = self
            .http
            .post(&url)
            .basic_auth(user, Some(pass))
            .send()
            .await
            .map_err(|e| AppError::UpstreamError(format!("Wazuh auth request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(AppError::UpstreamError(format!(
                "Wazuh auth returned {}",
                resp.status()
            )));
        }

        let body: AuthResponse = resp
            .json()
            .await
            .map_err(|e| AppError::UpstreamError(format!("Wazuh auth parse failed: {e}")))?;

        let token = body.data.token.clone();
        let exp = Instant::now() + Duration::from_secs(840);
        let mut guard = self.token_cache.write().await;
        *guard = Some(CachedToken {
            token: token.clone(),
            exp,
        });
        Ok(token)
    }

    async fn invalidate_token(&self) {
        let mut guard = self.token_cache.write().await;
        *guard = None;
    }

    pub async fn with_retry<F, Fut>(&self, f: F) -> AppResult<reqwest::Response>
    where
        F: Fn(String) -> Fut,
        Fut: Future<Output = AppResult<reqwest::RequestBuilder>>,
    {
        let max: u32 = 3;
        let mut delay = Duration::from_millis(500);
        for attempt in 1..=max {
            let token = self.acquire_token().await?;
            let builder = f(token).await?;
            match builder.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.as_u16() == 401 && attempt < max {
                        self.invalidate_token().await;
                        warn!(
                            attempt,
                            max, "Wazuh API returned 401; refreshing token and retrying"
                        );
                        tokio::time::sleep(delay).await;
                        delay = delay.saturating_mul(2);
                        continue;
                    }
                    if status.is_server_error() && attempt < max {
                        warn!(
                            attempt,
                            max,
                            status = %status,
                            "Wazuh API server error; retrying"
                        );
                        tokio::time::sleep(delay).await;
                        delay = delay.saturating_mul(2);
                        continue;
                    }
                    return Ok(resp);
                }
                Err(e) if (e.is_connect() || e.is_timeout()) && attempt < max => {
                    warn!(attempt, max, error = %e, "Wazuh API transient error; retrying");
                    tokio::time::sleep(delay).await;
                    delay = delay.saturating_mul(2);
                }
                Err(e) => return Err(e.into()),
            }
        }
        unreachable!("retry loop exhausted")
    }

    #[tracing::instrument(skip(self), fields(agent_id = %agent_id))]
    pub async fn send_active_response_raw(
        &self,
        agent_id: &str,
        command: &str,
    ) -> AppResult<ArOutcome> {
        let url = format!(
            "{}/active-response?agents_list={}",
            self.manager_url.trim_end_matches('/'),
            agent_id
        );
        let payload = serde_json::json!({
            "command": format!("!{}", command),
            "arguments": []
        });

        let resp = self
            .with_retry(|token| {
                let url = url.clone();
                let payload = payload.clone();
                async move { Ok(self.http.put(&url).bearer_auth(token).json(&payload)) }
            })
            .await?;

        let status = resp.status();
        let body_bytes = resp
            .bytes()
            .await
            .map_err(|e| AppError::UpstreamError(format!("AR response body read failed: {e}")))?;

        let ar_resp: ArResponse = serde_json::from_slice(&body_bytes).map_err(|e| {
            AppError::UpstreamError(format!(
                "AR response parse failed (status={}): {}",
                status, e
            ))
        })?;

        // Check for specific Wazuh error codes in failed_items
        if let Some(failed) = ar_resp.data.failed_items.first() {
            match failed.error.code {
                1707 => return Ok(ArOutcome::AgentOffline),
                1701 => return Ok(ArOutcome::AgentGone),
                _ => {}
            }
        }

        if ar_resp.data.total_affected_items > 0 {
            return Ok(ArOutcome::Sent);
        }

        Err(AppError::UpstreamError(format!(
            "AR command failed with status {} and error code {}",
            status, ar_resp.error
        )))
    }

    /// Returns the Wazuh agent ID for the given identifier (exact name or subject prefix).
    #[tracing::instrument(skip(self), fields(agent_name = %agent_name.as_deref().unwrap_or(""), subject = %subject))]
    pub async fn find_agent_id(
        &self,
        agent_name: Option<&str>,
        subject: &str,
    ) -> AppResult<Option<String>> {
        let name = match agent_name {
            Some(n) => n,
            None => return Ok(None),
        };
        let url = format!(
            "{}/agents?search={}",
            self.manager_url.trim_end_matches('/'),
            name
        );
        let resp = self
            .with_retry(|token| {
                let url = url.clone();
                async move { Ok(self.http.get(&url).bearer_auth(token)) }
            })
            .await?;

        if !resp.status().is_success() {
            return Err(AppError::UpstreamError(format!(
                "GET /agents returned {}",
                resp.status()
            )));
        }

        let body: AgentsResponse = resp
            .json()
            .await
            .map_err(|e| AppError::UpstreamError(format!("GET /agents parse failed: {e}")))?;

        info!(
            "Retrieved agents from manager: {:#?}",
            body.data.affected_items
        );

        for item in body.data.affected_items {
            if item.name == name {
                info!(agent_name = %name, agent_id = %item.id, "Found agent by name");
                return Ok(Some(item.id));
            }
        }

        Ok(None)
    }

    /// Remove the agent from the Wazuh manager.
    #[tracing::instrument(skip(self), fields(subject = %subject, agent_id = %agent_id))]
    pub async fn execute_delete_agent(&self, agent_id: &str, subject: &str) -> AppResult<()> {
        let url = format!(
            "{}/agents?agents_list={}&status=all&older_than=0s",
            self.manager_url.trim_end_matches('/'),
            agent_id
        );
        let resp = self
            .with_retry(|token| {
                let url = url.clone();
                async move { Ok(self.http.delete(&url).bearer_auth(token)) }
            })
            .await?;

        if !resp.status().is_success() {
            return Err(AppError::UpstreamError(format!(
                "DELETE /agents returned {}",
                resp.status()
            )));
        }
        info!(agent_id, subject, "Wazuh agent deleted");
        Ok(())
    }

    /// Resolve and delete the agent.
    pub async fn delete_agent(&self, agent_name: Option<&str>, subject: &str) -> AppResult<()> {
        if let Some(agent_id) = self.find_agent_id(agent_name, subject).await? {
            self.execute_delete_agent(&agent_id, subject).await?;
        } else {
            info!(
                subject,
                ?agent_name,
                "Agent not found in manager, skipping deletion"
            );
        }
        Ok(())
    }

    pub fn get_http_client(&self) -> &Client {
        &self.http
    }
}
