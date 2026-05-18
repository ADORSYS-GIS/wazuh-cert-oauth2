use super::ProxyState;
use super::oauth;
use super::spool;
use crate::state::spool::{ArPendingRequest, EvictRequest, GitHubTicket};
use wazuh_cert_oauth2_model::models::errors::{AppError, AppResult};
use wazuh_cert_oauth2_model::models::ledger_entry::LedgerEntry;
use wazuh_cert_oauth2_model::models::revoke_request::RevokeRequest;

impl ProxyState {
    #[tracing::instrument(skip(self, req), fields(subject = %req.subject.as_deref().unwrap_or(""), serial = %req.serial_hex.as_deref().unwrap_or("")))]
    pub async fn forward_revoke_with_retry(&self, req: RevokeRequest) -> AppResult<()> {
        let url = format!("{}/api/revoke", self.server_base_url.trim_end_matches('/'));
        let resp = self
            .execute_with_retry(|| async {
                let token = self.acquire_token().await?;
                let mut builder = self.http.client().post(&url).json(&req);
                if let Some(t) = token {
                    builder = builder.bearer_auth(t);
                }
                Ok(builder)
            })
            .await?;

        if resp.status().as_u16() == 401 {
            let mut guard = self.token_cache.write().await;
            *guard = None;
        }

        if !resp.status().is_success() {
            return Err(AppError::UpstreamError(resp.status().to_string()));
        }

        Ok(())
    }

    pub async fn execute_with_retry<F, Fut>(&self, f: F) -> AppResult<reqwest::Response>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = AppResult<reqwest::RequestBuilder>>,
    {
        let mut attempt: u32 = 0;
        let max = self.retry_attempts.max(1);
        let mut delay = self.retry_base;
        loop {
            attempt += 1;
            let builder: reqwest::RequestBuilder = f().await?;
            match builder.send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        return Ok(resp);
                    }
                    if resp.status().is_server_error() && attempt < max {
                        tracing::warn!(
                            "Upstream server error (status={}); retrying (attempt {}/{})",
                            resp.status(),
                            attempt,
                            max
                        );
                    } else {
                        return Ok(resp);
                    }
                }
                Err(e) if (e.is_connect() || e.is_timeout()) && attempt < max => {
                    tracing::warn!(
                        "Upstream connection error: {}; retrying (attempt {}/{})",
                        e,
                        attempt,
                        max
                    );
                }
                Err(e) => return Err(e.into()),
            }
            tokio::time::sleep(delay).await;
            delay = std::cmp::min(self.retry_max, delay.saturating_mul(2));
        }
    }

    #[tracing::instrument(skip(self, ticket))]
    pub async fn forward_github_ticket_with_retry(&self, ticket: GitHubTicket) -> AppResult<()> {
        let (token, owner, name) = match (
            &self.github_token,
            &self.github_repo_owner,
            &self.github_repo_name,
        ) {
            (Some(t), Some(o), Some(n)) => (t, o, n),
            _ => {
                tracing::warn!(
                    "Forwarding GitHub ticket requested but GitHub config is incomplete"
                );
                return Ok(());
            }
        };

        let url = format!("https://api.github.com/repos/{}/{}/issues", owner, name);
        let payload = serde_json::json!({
            "title": ticket.title,
            "body": ticket.body,
        });

        let resp = self
            .execute_with_retry(|| async {
                let builder = self
                    .http
                    .client()
                    .post(&url)
                    .header("User-Agent", "wazuh-cert-oauth2-webhook")
                    .header("Accept", "application/vnd.github.v3+json")
                    .bearer_auth(token)
                    .json(&payload);
                Ok(builder)
            })
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::error!(
                "failed to create GitHub ticket: upstream returned status={}, body={:?}",
                status,
                body
            );
            return Err(AppError::UpstreamError(format!(
                "GitHub ticket creation failed with status {}",
                status
            )));
        }

        tracing::info!("successfully created GitHub ticket");
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub(crate) async fn acquire_token(&self) -> AppResult<Option<String>> {
        if let Some(s) = &self.static_bearer {
            return Ok(Some(s.clone()));
        }
        if self.oauth.is_some() {
            return oauth::acquire_oauth_token(self).await;
        }
        Ok(None)
    }

    /// Delegate event parsing + action mapping to the IdP adapter.
    pub fn idp_parse_event(
        &self,
        headers: &rocket::http::HeaderMap<'_>,
        req: &serde_json::Value,
    ) -> crate::ports::idp::IdpEvent {
        self.idp.parse_event_with_headers(headers, req)
    }

    /// Extract user information from a webhook payload via the IdP adapter.
    pub fn idp_extract_user(
        &self,
        req: &serde_json::Value,
    ) -> AppResult<crate::models::SimpleUserRepresentation> {
        self.idp.extract_user(req)
    }

    /// Returns the configured revoke reason from the IdP adapter.
    pub fn revoke_reason(&self) -> String {
        self.idp.revoke_reason()
    }

    pub async fn queue_revoke(&self, req: RevokeRequest) -> AppResult<()> {
        spool::queue_revoke_to_spool_dir(self, req).await
    }

    pub async fn queue_github_ticket(&self, ticket: GitHubTicket) -> AppResult<()> {
        spool::queue_github_ticket_to_spool_dir(self, ticket).await
    }

    pub async fn queue_evict(&self, req: EvictRequest) -> AppResult<()> {
        spool::queue_evict_to_spool_dir(self, req).await
    }

    pub async fn queue_ar_pending(&self, req: ArPendingRequest) -> AppResult<()> {
        spool::queue_ar_pending_to_spool_dir(self, req).await
    }

    pub async fn fetch_ledger_by_subject(&self, subject: &str) -> AppResult<Vec<LedgerEntry>> {
        let url = format!(
            "{}/api/ledger/subject/{}",
            self.server_base_url.trim_end_matches('/'),
            subject
        );
        let resp = self
            .execute_with_retry(|| async {
                let token = self.acquire_token().await?;
                let mut builder = self.http.client().get(&url);
                if let Some(t) = token {
                    builder = builder.bearer_auth(t);
                }
                Ok(builder)
            })
            .await?;

        if !resp.status().is_success() {
            return Err(AppError::UpstreamError(format!(
                "GET /ledger/subject/{} failed with status {}",
                subject,
                resp.status()
            )));
        }

        let entries: Vec<LedgerEntry> = resp.json().await.map_err(|e| {
            AppError::UpstreamError(format!("failed to parse ledger entries: {}", e))
        })?;

        Ok(entries)
    }

    /// Delegates eviction to the WazuhApiClient if configured, otherwise logs a warning.
    pub async fn run_eviction_from_state(&self, req: EvictRequest) -> AppResult<()> {
        match &self.wazuh_api {
            Some(client) => {
                if let Some(ar_pending) = client.run_eviction(&req).await? {
                    self.queue_ar_pending(ar_pending).await?;
                }
                Ok(())
            }
            None => {
                tracing::warn!(
                    subject = %req.subject,
                    "Eviction requested but WAZUH_MANAGER_URL is not configured; skipping"
                );
                Ok(())
            }
        }
    }

    pub async fn run_ar_pending_from_state(&self, req: ArPendingRequest) -> AppResult<()> {
        match &self.wazuh_api {
            Some(client) => client.run_ar_pending(&req).await,
            None => {
                tracing::warn!(
                    agent_id = %req.agent_id,
                    "AR retry requested but Wazuh client is not configured; skipping"
                );
                Ok(())
            }
        }
    }
}
