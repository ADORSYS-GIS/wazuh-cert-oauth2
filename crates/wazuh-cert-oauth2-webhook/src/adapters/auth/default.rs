use crate::ports::utils::constant_time_eq;
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rocket::http::HeaderMap;
use std::collections::HashMap;
use tracing::{debug, info, warn};

use crate::ports::webhook_auth::{AuthOutcome, WebhookAuthProvider};

/// Default webhook auth adapter — supports five auth methods:
/// 1. Anonymous (no credentials configured)
/// 2. X-API-KEY header
/// 3. Authorization: Bearer <token>
/// 4. Authorization: Basic <base64>
/// 5. Custom request headers (map of header-name → expected value)
///
/// This adapter never returns `NotApplicable` — it is the universal fallback.
#[derive(Clone, Debug)]
pub struct DefaultWebhookAuthProvider {
    pub webhook_basic_user: Option<String>,
    pub webhook_basic_password: Option<String>,
    pub webhook_api_key: Option<String>,
    pub webhook_bearer_token: Option<String>,
    pub webhook_custom_headers: HashMap<String, String>,
}

impl DefaultWebhookAuthProvider {
    pub fn new(
        webhook_basic_user: Option<String>,
        webhook_basic_password: Option<String>,
        webhook_api_key: Option<String>,
        webhook_bearer_token: Option<String>,
        webhook_custom_headers: HashMap<String, String>,
    ) -> Self {
        Self {
            webhook_basic_user,
            webhook_basic_password,
            webhook_api_key,
            webhook_bearer_token,
            webhook_custom_headers,
        }
    }

    pub fn from_opt(opt: &crate::opts::Opt) -> Self {
        Self::new(
            opt.webhook_basic_user.clone(),
            opt.webhook_basic_password.clone(),
            opt.webhook_api_key.clone(),
            opt.webhook_bearer_token.clone(),
            opt.webhook_custom_headers.iter().cloned().collect(),
        )
    }

    /// Returns `true` when no credential-based auth is configured
    fn is_anonymous(&self) -> bool {
        self.webhook_basic_user.is_none()
            && self.webhook_basic_password.is_none()
            && self.webhook_api_key.is_none()
            && self.webhook_bearer_token.is_none()
            && self.webhook_custom_headers.is_empty()
    }

    /// Returns `true` if every configured custom header is present in
    /// `headers` with the expected value (constant-time comparison).
    fn custom_headers_match(&self, headers: &HeaderMap<'_>) -> bool {
        self.webhook_custom_headers.iter().all(|(name, expected)| {
            headers
                .get_one(name.as_str())
                .map(|v| constant_time_eq(v, expected))
                .unwrap_or(false)
        })
    }
}

#[async_trait]
impl WebhookAuthProvider for DefaultWebhookAuthProvider {
    async fn authenticate(&self, headers: &HeaderMap<'_>) -> AuthOutcome {
        // 1. Custom header gate — if configured, ALL must be present and match.
        if !self.webhook_custom_headers.is_empty() {
            if self.custom_headers_match(headers) {
                info!("Webhook auth: custom headers validated");
                return AuthOutcome::Authenticated;
            }
            debug!("Webhook auth: custom headers validation failed");
            return AuthOutcome::Denied;
        }

        // 2. Anonymous — no credentials of any kind configured.
        if self.is_anonymous() {
            info!("Webhook auth: anonymous allowed by config");
            return AuthOutcome::Authenticated;
        }

        // 3. X-API-KEY header
        if let Some(cfg_key) = &self.webhook_api_key
            && let Some(h) = headers.get_one("X-API-KEY")
        {
            if constant_time_eq(h, cfg_key) {
                info!("Webhook auth: X-API-KEY validated");
                return AuthOutcome::Authenticated;
            }
            debug!("Webhook auth: X-API-KEY present but invalid");
            return AuthOutcome::Denied;
        }

        // 4 & 5. Authorization header
        if let Some(authz) = headers.get_one("Authorization") {
            if let Some(token) = authz.strip_prefix("Bearer ") {
                if let Some(cfg) = &self.webhook_bearer_token
                    && constant_time_eq(token, cfg)
                {
                    info!("Webhook auth: Bearer token validated");
                    return AuthOutcome::Authenticated;
                }
                debug!("Webhook auth: Bearer token failed validation");
                return AuthOutcome::Denied;
            }

            if let Some(b64) = authz.strip_prefix("Basic ")
                && let (Some(u), Some(p)) = (&self.webhook_basic_user, &self.webhook_basic_password)
            {
                if let Ok(decoded) = B64.decode(b64.as_bytes())
                    && let Ok(s) = String::from_utf8(decoded)
                {
                    let mut parts = s.splitn(2, ':');
                    let user_ok = parts
                        .next()
                        .map(|x| constant_time_eq(x, u))
                        .unwrap_or(false);
                    let pass_ok = parts
                        .next()
                        .map(|x| constant_time_eq(x, p))
                        .unwrap_or(false);
                    if user_ok && pass_ok {
                        info!("Webhook auth: Basic credentials validated");
                        return AuthOutcome::Authenticated;
                    }
                }
                debug!("Webhook auth: Basic credentials invalid");
                return AuthOutcome::Denied;
            }
        }

        warn!("Webhook auth: unauthorized request — no valid credentials");
        AuthOutcome::Denied
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use rocket::http::Header;

    fn headers_with(pairs: &[(&str, &str)]) -> rocket::http::HeaderMap<'static> {
        let mut map = rocket::http::HeaderMap::new();
        for (k, v) in pairs {
            map.add(Header::new(k.to_string(), v.to_string()));
        }
        map
    }

    fn basic(user: &str, pass: &str) -> String {
        format!(
            "Basic {}",
            B64.encode(format!("{}:{}", user, pass).as_bytes())
        )
    }

    // 1. Anonymous
    #[tokio::test]
    async fn anonymous_when_no_credentials_configured() {
        let p = DefaultWebhookAuthProvider::new(None, None, None, None, HashMap::new());
        let h = headers_with(&[]);
        assert_eq!(p.authenticate(&h).await, AuthOutcome::Authenticated);
    }

    // 2. X-API-KEY
    #[tokio::test]
    async fn api_key_authenticated_when_matching() {
        let p = DefaultWebhookAuthProvider::new(
            None,
            None,
            Some("secret".to_string()),
            None,
            HashMap::new(),
        );
        let h = headers_with(&[("X-API-KEY", "secret")]);
        assert_eq!(p.authenticate(&h).await, AuthOutcome::Authenticated);
    }

    #[tokio::test]
    async fn api_key_denied_when_wrong() {
        let p = DefaultWebhookAuthProvider::new(
            None,
            None,
            Some("secret".to_string()),
            None,
            HashMap::new(),
        );
        let h = headers_with(&[("X-API-KEY", "wrong")]);
        assert_eq!(p.authenticate(&h).await, AuthOutcome::Denied);
    }

    // 3. Bearer
    #[tokio::test]
    async fn bearer_authenticated_when_matching() {
        let p = DefaultWebhookAuthProvider::new(
            None,
            None,
            None,
            Some("tok".to_string()),
            HashMap::new(),
        );
        let h = headers_with(&[("Authorization", "Bearer tok")]);
        assert_eq!(p.authenticate(&h).await, AuthOutcome::Authenticated);
    }

    #[tokio::test]
    async fn bearer_denied_when_wrong() {
        let p = DefaultWebhookAuthProvider::new(
            None,
            None,
            None,
            Some("tok".to_string()),
            HashMap::new(),
        );
        let h = headers_with(&[("Authorization", "Bearer bad")]);
        assert_eq!(p.authenticate(&h).await, AuthOutcome::Denied);
    }

    // 4. Basic
    #[tokio::test]
    async fn basic_authenticated_when_correct() {
        let p = DefaultWebhookAuthProvider::new(
            Some("user".to_string()),
            Some("pass".to_string()),
            None,
            None,
            HashMap::new(),
        );
        let h = headers_with(&[("Authorization", &basic("user", "pass"))]);
        assert_eq!(p.authenticate(&h).await, AuthOutcome::Authenticated);
    }

    #[tokio::test]
    async fn basic_denied_when_wrong_password() {
        let p = DefaultWebhookAuthProvider::new(
            Some("user".to_string()),
            Some("pass".to_string()),
            None,
            None,
            HashMap::new(),
        );
        let h = headers_with(&[("Authorization", &basic("user", "bad"))]);
        assert_eq!(p.authenticate(&h).await, AuthOutcome::Denied);
    }

    #[tokio::test]
    async fn denied_when_credentials_configured_but_no_header() {
        let p = DefaultWebhookAuthProvider::new(
            Some("user".to_string()),
            Some("pass".to_string()),
            None,
            None,
            HashMap::new(),
        );
        let h = headers_with(&[]);
        assert_eq!(p.authenticate(&h).await, AuthOutcome::Denied);
    }

    // 5. Custom headers
    #[tokio::test]
    async fn custom_headers_authenticated_when_all_match() {
        let headers_cfg = [
            ("X-Webhook-Secret".to_string(), "my-secret".to_string()),
            ("X-Tenant-ID".to_string(), "tenant-42".to_string()),
        ]
        .into_iter()
        .collect::<HashMap<_, _>>();
        let p = DefaultWebhookAuthProvider::new(None, None, None, None, headers_cfg);
        let h = headers_with(&[
            ("X-Webhook-Secret", "my-secret"),
            ("X-Tenant-ID", "tenant-42"),
        ]);
        assert_eq!(p.authenticate(&h).await, AuthOutcome::Authenticated);
    }

    #[tokio::test]
    async fn custom_headers_denied_when_value_wrong() {
        let headers_cfg = [("X-Webhook-Secret".to_string(), "my-secret".to_string())]
            .into_iter()
            .collect::<HashMap<_, _>>();
        let p = DefaultWebhookAuthProvider::new(None, None, None, None, headers_cfg);
        let h = headers_with(&[("X-Webhook-Secret", "wrong")]);
        assert_eq!(p.authenticate(&h).await, AuthOutcome::Denied);
    }

    #[tokio::test]
    async fn custom_headers_denied_when_header_missing() {
        let headers_cfg = [("X-Webhook-Secret".to_string(), "my-secret".to_string())]
            .into_iter()
            .collect::<HashMap<_, _>>();
        let p = DefaultWebhookAuthProvider::new(None, None, None, None, headers_cfg);
        let h = headers_with(&[]);
        assert_eq!(p.authenticate(&h).await, AuthOutcome::Denied);
    }

    // Gate semantics: custom headers are a self-contained auth method.
    // When configured they take full control — other credential fields don't matter.
    #[tokio::test]
    async fn custom_header_gate_denies_wrong_header_even_with_basic_in_config() {
        let headers_cfg = [("X-Webhook-Secret".to_string(), "my-secret".to_string())]
            .into_iter()
            .collect::<HashMap<_, _>>();
        let p = DefaultWebhookAuthProvider::new(
            Some("user".to_string()),
            Some("pass".to_string()),
            None,
            None,
            headers_cfg,
        );
        // Wrong custom header → Denied, even though Basic would otherwise pass
        let h = headers_with(&[
            ("X-Webhook-Secret", "wrong"),
            ("Authorization", &basic("user", "pass")),
        ]);
        assert_eq!(p.authenticate(&h).await, AuthOutcome::Denied);
    }

    #[tokio::test]
    async fn custom_header_sufficient_even_when_other_credentials_in_config() {
        let headers_cfg = [("X-Webhook-Secret".to_string(), "my-secret".to_string())]
            .into_iter()
            .collect::<HashMap<_, _>>();
        let p = DefaultWebhookAuthProvider::new(
            Some("user".to_string()),
            Some("pass".to_string()),
            None,
            None,
            headers_cfg,
        );
        // Correct custom header alone → Authenticated, no need to also send Basic
        let h = headers_with(&[("X-Webhook-Secret", "my-secret")]);
        assert_eq!(p.authenticate(&h).await, AuthOutcome::Authenticated);
    }
}
