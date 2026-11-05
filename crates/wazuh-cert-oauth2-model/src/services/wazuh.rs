use reqwest::Client;
use serde::Deserialize;
use std::future::Future;
use std::path::PathBuf;
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
    #[serde(default)]
    total_affected_items: usize,
}

#[derive(Deserialize, Debug, Clone)]
pub struct AgentItem {
    pub id: String,
    pub name: String,
    pub os: Option<OSInfo>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct OSInfo {
    #[serde(default)]
    pub platform: String,
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
        // TLS verification enabled by default.
        Self::with_tls_options(manager_url, user, password, static_token, true, None)
    }

    /// Create a `WazuhClient` with explicit TLS verification controls.
    ///
    /// - `tls_verify`: when `true`, the client validates the Wazuh Manager's
    ///   TLS certificate against the system trust store (or `ca_bundle` if
    ///   provided). When `false`, invalid certs are accepted (insecure).
    /// - `ca_bundle`: optional path to a PEM file containing additional CA
    ///   certificates to trust (e.g. for self-signed Wazuh managers).
    pub fn with_tls_options(
        manager_url: String,
        user: Option<String>,
        password: Option<String>,
        static_token: Option<String>,
        tls_verify: bool,
        ca_bundle: Option<PathBuf>,
    ) -> Self {
        let mut builder = Client::builder().timeout(Duration::from_secs(30));

        if !tls_verify {
            builder = builder.danger_accept_invalid_certs(true);
        }

        if let Some(ref ca_path) = ca_bundle {
            match std::fs::read(ca_path) {
                Ok(pem) => match reqwest::Certificate::from_pem(&pem) {
                    Ok(cert) => {
                        builder = builder.add_root_certificate(cert);
                    }
                    Err(e) => {
                        warn!(
                            path = %ca_path.display(),
                            error = %e,
                            "Failed to parse CA bundle; falling back to system trust store"
                        );
                    }
                },
                Err(e) => {
                    warn!(
                        path = %ca_path.display(),
                        error = %e,
                        "Failed to read CA bundle file; falling back to system trust store"
                    );
                }
            }
        }

        Self {
            manager_url,
            user,
            password,
            static_token,
            token_cache: Arc::new(RwLock::new(None)),
            http: builder.build().expect("reqwest client"),
        }
    }

    async fn acquire_token(&self) -> AppResult<String> {
        if self.user.is_none() || self.password.is_none() {
            return self.static_token.clone().ok_or_else(|| {
                AppError::UpstreamError("No Wazuh API credentials configured".into())
            });
        }

        if let Some(cached) = (*self.token_cache.read().await).clone()
            && Instant::now() < cached.exp
        {
            return Ok(cached.token);
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

    /// Returns the Wazuh agent details for the given identifier (exact name or subject prefix).
    #[tracing::instrument(skip(self), fields(agent_name = %agent_name.unwrap_or(""), subject = %subject))]
    pub async fn find_agent(
        &self,
        agent_name: Option<&str>,
        subject: &str,
    ) -> AppResult<Option<AgentItem>> {
        let name = match agent_name {
            Some(n) => n,
            None => return Ok(None),
        };
        // Use reqwest's .query() for proper URL-encoding of the agent name, and
        // Wazuh query language (q=name=<exact>) for an exact match
        let base = format!("{}/agents", self.manager_url.trim_end_matches('/'));
        let name = name.to_string();
        let query = format!("name={}", name);
        let resp = self
            .with_retry(|token| {
                let base = base.clone();
                let query = query.clone();
                async move {
                    Ok(self
                        .http
                        .get(&base)
                        .query(&[("q", query.as_str())])
                        .bearer_auth(token))
                }
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
                return Ok(Some(item));
            }
        }

        Ok(None)
    }

    /// Fetch all agents from the Wazuh Manager.
    ///
    /// Handles pagination via `offset`/`limit` to avoid silently truncating
    /// fleets larger than the API's default page size (500 agents).
    #[tracing::instrument(skip(self))]
    pub async fn list_agents(&self) -> AppResult<Vec<AgentItem>> {
        let base = format!("{}/agents", self.manager_url.trim_end_matches('/'));
        let page_size: usize = 500;
        let mut offset: usize = 0;
        let mut all_agents: Vec<AgentItem> = Vec::new();

        loop {
            let offset_str = offset.to_string();
            let limit_str = page_size.to_string();
            let resp = self
                .with_retry(|token| {
                    let base = base.clone();
                    let offset_str = offset_str.clone();
                    let limit_str = limit_str.clone();
                    async move {
                        Ok(self
                            .http
                            .get(&base)
                            .query(&[
                                ("offset", offset_str.as_str()),
                                ("limit", limit_str.as_str()),
                            ])
                            .bearer_auth(token))
                    }
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

            let count = body.data.affected_items.len();
            all_agents.extend(body.data.affected_items);

            let total = body.data.total_affected_items;
            if offset + count >= total || count == 0 {
                break;
            }
            offset += count;
        }

        info!("Retrieved {} agents from Wazuh Manager", all_agents.len());
        Ok(all_agents)
    }

    /// Remove the agent from the Wazuh manager.
    #[tracing::instrument(skip(self), fields(subject = %subject, agent_id = %agent_id))]
    pub async fn execute_delete_agent(&self, agent_id: &str, subject: &str) -> AppResult<()> {
        // Use reqwest's .query() for proper URL-encoding.
        let base = format!("{}/agents", self.manager_url.trim_end_matches('/'));
        let agent_id = agent_id.to_string();
        let resp = self
            .with_retry(|token| {
                let base = base.clone();
                let agent_id = agent_id.clone();
                async move {
                    Ok(self
                        .http
                        .delete(&base)
                        .query(&[
                            ("agents_list", agent_id.as_str()),
                            ("status", "all"),
                            ("older_than", "0s"),
                        ])
                        .bearer_auth(token))
                }
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
        if let Some(agent) = self.find_agent(agent_name, subject).await? {
            self.execute_delete_agent(&agent.id, subject).await?;
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

#[cfg(test)]
mod tests {
    use super::WazuhClient;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client(
        manager_url: &str,
        user: Option<&str>,
        password: Option<&str>,
        static_token: Option<&str>,
    ) -> WazuhClient {
        WazuhClient::new(
            manager_url.to_string(),
            user.map(|s| s.to_string()),
            password.map(|s| s.to_string()),
            static_token.map(|s| s.to_string()),
        )
    }

    fn auth_mock() -> Mock {
        Mock::given(method("POST"))
            .and(path("/security/user/authenticate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "token": "wazuh-token" }
            })))
    }

    #[tokio::test]
    async fn acquire_token_returns_static_token_when_no_credentials() {
        let server = MockServer::start().await;
        let c = client(&server.uri(), None, None, Some("static-token"));
        let token = c
            .acquire_token()
            .await
            .expect("static token should be returned");
        assert_eq!(token, "static-token");
    }

    #[tokio::test]
    async fn acquire_token_errors_without_credentials_or_static_token() {
        let server = MockServer::start().await;
        let c = client(&server.uri(), None, None, None);
        assert!(c.acquire_token().await.is_err());
    }

    #[tokio::test]
    async fn fetch_and_cache_token_authenticates_and_caches() {
        let server = MockServer::start().await;
        auth_mock().mount(&server).await;

        let c = client(&server.uri(), Some("user"), Some("pass"), None);
        let token = c.acquire_token().await.expect("token should be fetched");
        assert_eq!(token, "wazuh-token");

        // Second call should hit the cache without another HTTP request.
        let token2 = c.acquire_token().await.expect("cached token");
        assert_eq!(token2, "wazuh-token");
    }

    #[tokio::test]
    async fn find_agent_returns_matching_agent() {
        let server = MockServer::start().await;
        auth_mock().mount(&server).await;
        Mock::given(method("GET"))
            .and(path("/agents"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "affected_items": [
                        {"id": "001", "name": "alice-abc", "os": {"platform": "linux"}},
                        {"id": "002", "name": "bob-def", "os": null}
                    ],
                    "total_affected_items": 2
                }
            })))
            .mount(&server)
            .await;

        let c = client(&server.uri(), Some("user"), Some("pass"), None);
        let agent = c
            .find_agent(Some("alice-abc"), "sub")
            .await
            .expect("find should succeed")
            .expect("agent should be found");
        assert_eq!(agent.id, "001");
        assert_eq!(agent.name, "alice-abc");
    }

    #[tokio::test]
    async fn find_agent_returns_none_when_no_match() {
        let server = MockServer::start().await;
        auth_mock().mount(&server).await;
        Mock::given(method("GET"))
            .and(path("/agents"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "affected_items": [{"id": "001", "name": "other"}], "total_affected_items": 1 }
            })))
            .mount(&server)
            .await;

        let c = client(&server.uri(), Some("user"), Some("pass"), None);
        let agent = c
            .find_agent(Some("missing"), "sub")
            .await
            .expect("find should succeed");
        assert!(agent.is_none());
    }

    #[tokio::test]
    async fn find_agent_returns_none_when_name_is_none() {
        let server = MockServer::start().await;
        let c = client(&server.uri(), Some("user"), Some("pass"), None);
        let agent = c
            .find_agent(None, "sub")
            .await
            .expect("find should succeed");
        assert!(agent.is_none());
    }

    #[tokio::test]
    async fn list_agents_handles_pagination() {
        let server = MockServer::start().await;
        auth_mock().mount(&server).await;
        // First page returns 1 agent with total 2, second page returns the rest.
        Mock::given(method("GET"))
            .and(path("/agents"))
            .and(wiremock::matchers::query_param("offset", "0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "affected_items": [{"id": "001", "name": "a"}], "total_affected_items": 2 }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/agents"))
            .and(wiremock::matchers::query_param("offset", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "affected_items": [{"id": "002", "name": "b"}], "total_affected_items": 2 }
            })))
            .mount(&server)
            .await;

        let c = client(&server.uri(), Some("user"), Some("pass"), None);
        let agents = c.list_agents().await.expect("list should succeed");
        assert_eq!(agents.len(), 2);
        assert_eq!(agents[0].id, "001");
        assert_eq!(agents[1].id, "002");
    }

    #[tokio::test]
    async fn execute_delete_agent_succeeds() {
        let server = MockServer::start().await;
        auth_mock().mount(&server).await;
        Mock::given(method("DELETE"))
            .and(path("/agents"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "affected_items": [{"id": "001"}], "total_affected_items": 1 }
            })))
            .mount(&server)
            .await;

        let c = client(&server.uri(), Some("user"), Some("pass"), None);
        c.execute_delete_agent("001", "sub")
            .await
            .expect("delete should succeed");
    }

    #[tokio::test]
    async fn with_retry_retries_on_server_error_then_succeeds() {
        let server = MockServer::start().await;
        auth_mock().mount(&server).await;
        // First /agents call returns 500 (retried), second returns 200.
        Mock::given(method("GET"))
            .and(path("/agents"))
            .respond_with(ResponseTemplate::new(500))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/agents"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "affected_items": [], "total_affected_items": 0 }
            })))
            .mount(&server)
            .await;

        let c = client(&server.uri(), Some("user"), Some("pass"), None);
        let agents = c
            .list_agents()
            .await
            .expect("list should succeed after retry");
        assert!(agents.is_empty());
    }
}
