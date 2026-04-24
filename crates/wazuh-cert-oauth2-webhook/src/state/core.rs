use super::ProxyState;
use super::oauth;
use super::spool;
use crate::models::WebhookRequest;
use crate::state::spool::GitHubTicket;
use wazuh_cert_oauth2_model::models::errors::{AppError, AppResult};
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
    async fn acquire_token(&self) -> AppResult<Option<String>> {
        if let Some(s) = &self.static_bearer {
            return Ok(Some(s.clone()));
        }
        if self.oauth.is_some() {
            return oauth::acquire_oauth_token(self).await;
        }
        Ok(None)
    }

    #[tracing::instrument(skip(self, webhook_request), fields(event_type = %event_type_lower))]
    pub fn is_allowed_event(
        &self,
        event_type_lower: &str,
        webhook_request: &WebhookRequest,
    ) -> EventAction {
        let t = event_type_lower;
        if t == "user-update" || t == "user-delete" {
            if let Some(rp) = &webhook_request.resource_path
                && !rp.contains("users/")
            {
                return EventAction::Ignore;
            }

            if t == "user-update"
                && let Ok(user) = webhook_request.get_simple_user_representation()
                && user.enabled
            {
                return EventAction::Enabled;
            }

            return EventAction::Revoke;
        }

        if t == "register" || t == "user-create" {
            return EventAction::CreateTicket;
        }

        EventAction::Ignore
    }

    pub fn revoke_reason(&self) -> Option<String> {
        Some(self.revoke_reason.clone())
    }

    pub fn webhook_allows_anonymous(&self) -> bool {
        self.webhook_basic_user.is_none()
            && self.webhook_basic_password.is_none()
            && self.webhook_api_key.is_none()
            && self.webhook_bearer_token.is_none()
    }
    pub fn webhook_basic_user(&self) -> Option<&str> {
        self.webhook_basic_user.as_deref()
    }
    pub fn webhook_basic_password(&self) -> Option<&str> {
        self.webhook_basic_password.as_deref()
    }
    pub fn webhook_api_key(&self) -> Option<&str> {
        self.webhook_api_key.as_deref()
    }
    pub fn webhook_bearer_token(&self) -> Option<&str> {
        self.webhook_bearer_token.as_deref()
    }

    pub async fn queue_revoke(&self, req: RevokeRequest) -> AppResult<()> {
        spool::queue_revoke_to_spool_dir(self, req).await
    }

    pub async fn queue_github_ticket(&self, ticket: GitHubTicket) -> AppResult<()> {
        spool::queue_github_ticket_to_spool_dir(self, ticket).await
    }

    pub async fn cancel_pending_revokes_for_subject(&self, subject: &str) -> AppResult<usize> {
        spool::cancel_pending_revokes_for_subject(self, subject).await
    }
}

#[derive(Clone, PartialOrd, PartialEq, Debug)]
pub enum EventAction {
    Revoke,
    Enabled,
    Ignore,
    CreateTicket,
}

#[cfg(test)]
mod tests {
    use super::{EventAction, ProxyState};
    use crate::models::WebhookRequest;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use wazuh_cert_oauth2_model::services::http_client::HttpClient;

    fn unique_spool_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        std::env::temp_dir().join(format!("wazuh-webhook-state-core-{}", nanos))
    }

    fn build_state(
        webhook_api_key: Option<String>,
        webhook_bearer_token: Option<String>,
        webhook_basic_user: Option<String>,
        webhook_basic_password: Option<String>,
    ) -> ProxyState {
        ProxyState::new(
            "https://server.example".to_string(),
            unique_spool_dir(),
            HttpClient::new_with_defaults().expect("http client"),
            2,
            Duration::from_millis(5),
            Duration::from_millis(20),
            Duration::from_secs(1),
            None,
            None,
            None,
            None,
            None,
            None,
            "test reason".to_string(),
            webhook_basic_user,
            webhook_basic_password,
            webhook_api_key,
            webhook_bearer_token,
            None,
            None,
            None,
        )
        .expect("state should build")
    }

    fn webhook_request(
        event_type: &str,
        resource_path: Option<&str>,
        representation: Option<&str>,
    ) -> WebhookRequest {
        WebhookRequest {
            event_type: event_type.to_string(),
            realm_id: "realm".to_string(),
            id: None,
            time: None,
            client_id: None,
            ip_address: None,
            error: None,
            details: Some(HashMap::new()),
            resource_path: resource_path.map(|s| s.to_string()),
            representation: representation.map(|s| s.to_string()),
        }
    }

    #[test]
    fn user_delete_event_with_user_path_is_revoked() {
        let state = build_state(None, None, None, None);
        let req = webhook_request("user-delete", Some("admin/realms/x/users/u1"), None);

        let action = state.is_allowed_event("user-delete", &req);
        assert_eq!(action, EventAction::Revoke);
    }

    #[test]
    fn user_update_for_enabled_user_maps_to_enabled_action() {
        let state = build_state(None, None, None, None);
        let req = webhook_request(
            "user-update",
            Some("admin/realms/x/users/u1"),
            Some(r#"{"id":"u1","enabled":true,"username":"alice","email":"a@example.com"}"#),
        );

        let action = state.is_allowed_event("user-update", &req);
        assert_eq!(action, EventAction::Enabled);
    }

    #[test]
    fn non_user_resource_paths_are_ignored() {
        let state = build_state(None, None, None, None);
        let req = webhook_request("user-update", Some("admin/realms/x/groups/g1"), None);

        let action = state.is_allowed_event("user-update", &req);
        assert_eq!(action, EventAction::Ignore);
    }

    #[test]
    fn webhook_allows_anonymous_only_when_no_credentials_are_configured() {
        let anonymous = build_state(None, None, None, None);
        assert!(anonymous.webhook_allows_anonymous());

        let with_api_key = build_state(Some("secret-key".to_string()), None, None, None);
        assert!(!with_api_key.webhook_allows_anonymous());
        assert_eq!(with_api_key.webhook_api_key(), Some("secret-key"));
    }

    #[test]
    fn register_event_maps_to_create_ticket_action() {
        let state = build_state(None, None, None, None);
        let req = webhook_request("REGISTER", None, None);

        let action = state.is_allowed_event("register", &req);
        assert_eq!(action, EventAction::CreateTicket);
    }

    #[test]
    fn user_create_event_maps_to_create_ticket_action() {
        let state = build_state(None, None, None, None);
        let req = webhook_request("USER-CREATE", None, None);

        let action = state.is_allowed_event("user-create", &req);
        assert_eq!(action, EventAction::CreateTicket);
    }
}
