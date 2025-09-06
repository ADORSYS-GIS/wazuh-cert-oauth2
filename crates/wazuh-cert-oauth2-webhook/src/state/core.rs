use super::oauth;
use super::spool;
use super::ProxyState;
use crate::models::WebhookRequest;
use wazuh_cert_oauth2_model::models::errors::{AppError, AppResult};
use wazuh_cert_oauth2_model::models::revoke_request::RevokeRequest;

impl ProxyState {
    #[tracing::instrument(skip(self, req), fields(subject = %req.subject.as_deref().unwrap_or(""), serial = %req.serial_hex.as_deref().unwrap_or("")))]
    pub async fn forward_revoke_with_retry(&self, req: RevokeRequest) -> AppResult<()> {
        let url = format!("{}/api/revoke", self.server_base_url.trim_end_matches('/'));
        let mut attempt: u32 = 0;
        let max = self.retry_attempts.max(1);
        let mut delay = self.retry_base;
        loop {
            attempt += 1;
            match self.try_send(&url, &req).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if attempt >= max {
                        return Err(e);
                    }
                    tokio::time::sleep(delay).await;
                    delay = std::cmp::min(self.retry_max, delay.saturating_mul(2));
                }
            }
        }
    }

    #[tracing::instrument(skip(self, req))]
    async fn try_send(&self, url: &str, req: &RevokeRequest) -> AppResult<()> {
        let token = self.acquire_token().await?;
        let builder = self.http.client().post(url).json(req);
        let builder = if let Some(t) = token {
            builder.bearer_auth(t)
        } else {
            builder
        };

        let resp = builder.send().await?;
        if resp.status().as_u16() == 401 {
            let mut guard = self.token_cache.write().await;
            *guard = None;
        }

        if !resp.status().is_success() {
            return Err(AppError::UpstreamError(resp.status().to_string()));
        }

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

    pub async fn cancel_pending_revokes_for_subject(&self, subject: &str) -> AppResult<usize> {
        spool::cancel_pending_revokes_for_subject(self, subject).await
    }
}

#[derive(Clone, PartialOrd, PartialEq, Debug)]
pub enum EventAction {
    Revoke,
    Enabled,
    Ignore,
}
