use std::sync::Arc;

use async_trait::async_trait;
use rocket::http::HeaderMap;
use tracing::{debug, info};

use crate::adapters::auth::default::DefaultWebhookAuthProvider;
use crate::ports::utils::constant_time_eq;
use crate::ports::webhook_auth::{AuthOutcome, WebhookAuthProvider};

/// Google Workspace Directory API / Google Cloud Monitoring webhook auth adapter.
///
/// Behaviour:
/// - If `X-Goog-Channel-ID` and `X-Goog-Channel-Token` are both absent → `NotApplicable`
///   (delegates to the inner `DefaultWebhookAuthProvider`).
/// - If both are present → compare against configured values using constant-time comparison.
///   Returns `Authenticated` or `Denied`.
/// - Also handles the Google sync message (`X-Goog-Resource-State: sync`) alongside valid
///   Google headers as `Authenticated`.
pub struct GoogleWebhookAuthProvider {
    pub channel_id: String,
    pub channel_token: String,
    pub fallback: Arc<DefaultWebhookAuthProvider>,
}

impl GoogleWebhookAuthProvider {
    fn try_google_auth(&self, headers: &HeaderMap<'_>) -> AuthOutcome {
        let goog_id = headers.get_one("X-Goog-Channel-ID");
        let goog_token = headers.get_one("X-Goog-Channel-Token");

        match (goog_id, goog_token) {
            (Some(id), Some(token)) => {
                let id_ok = constant_time_eq(id, &self.channel_id);
                let tok_ok = constant_time_eq(token, &self.channel_token);

                if id_ok && tok_ok {
                    if let Some(state) = headers.get_one("X-Goog-Resource-State")
                        && state == "sync"
                    {
                        debug!("Webhook auth: Google sync message authenticated");
                    }
                    info!("Webhook auth: Google channel headers validated");
                    AuthOutcome::Authenticated
                } else {
                    debug!("Webhook auth: Google channel headers present but invalid");
                    AuthOutcome::Denied
                }
            }
            // One or both Google headers absent → not our auth scheme
            _ => AuthOutcome::NotApplicable,
        }
    }
}

#[async_trait]
impl WebhookAuthProvider for GoogleWebhookAuthProvider {
    async fn authenticate(&self, headers: &HeaderMap<'_>) -> AuthOutcome {
        match self.try_google_auth(headers) {
            AuthOutcome::NotApplicable => self.fallback.authenticate(headers).await,
            outcome => outcome,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocket::http::Header;

    fn make_provider(
        channel_id: &str,
        channel_token: &str,
        basic_user: Option<&str>,
        basic_pass: Option<&str>,
    ) -> GoogleWebhookAuthProvider {
        GoogleWebhookAuthProvider {
            channel_id: channel_id.to_string(),
            channel_token: channel_token.to_string(),
            fallback: Arc::new(DefaultWebhookAuthProvider::new(
                basic_user.map(|s| s.to_string()),
                basic_pass.map(|s| s.to_string()),
                None,
                None,
                std::collections::HashMap::new(),
            )),
        }
    }

    fn headers_with(pairs: &[(&str, &str)]) -> rocket::http::HeaderMap<'static> {
        let mut map = rocket::http::HeaderMap::new();
        for (k, v) in pairs {
            map.add(Header::new(k.to_string(), v.to_string()));
        }
        map
    }

    fn basic_b64(user: &str, pass: &str) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", user, pass).as_bytes())
    }

    // Valid Google headers
    #[tokio::test]
    async fn valid_google_headers_returns_authenticated() {
        let p = make_provider("chan-id", "chan-tok", None, None);
        let h = headers_with(&[
            ("X-Goog-Channel-ID", "chan-id"),
            ("X-Goog-Channel-Token", "chan-tok"),
        ]);
        assert_eq!(p.authenticate(&h).await, AuthOutcome::Authenticated);
    }

    // Invalid Google headers
    #[tokio::test]
    async fn invalid_google_headers_returns_denied() {
        let p = make_provider("chan-id", "chan-tok", None, None);
        let h = headers_with(&[
            ("X-Goog-Channel-ID", "chan-id"),
            ("X-Goog-Channel-Token", "WRONG"),
        ]);
        assert_eq!(p.authenticate(&h).await, AuthOutcome::Denied);
    }

    // Absent Google headers → must return NotApplicable (not Denied!)
    #[tokio::test]
    async fn absent_google_headers_returns_not_applicable_before_fallback() {
        let p = make_provider("chan-id", "chan-tok", None, None);
        // No X-Goog headers at all, no fallback credentials either → fallback returns Denied
        let h = headers_with(&[]);
        // The provider has no fallback creds, so it should ultimately return Denied via fallback
        // But the *google* part must return NotApplicable internally
        let inner = p.try_google_auth(&h);
        assert_eq!(inner, AuthOutcome::NotApplicable);
    }

    // Sync message passthrough
    #[tokio::test]
    async fn sync_message_with_valid_headers_is_authenticated() {
        let p = make_provider("chan-id", "chan-tok", None, None);
        let h = headers_with(&[
            ("X-Goog-Channel-ID", "chan-id"),
            ("X-Goog-Channel-Token", "chan-tok"),
            ("X-Goog-Resource-State", "sync"),
        ]);
        assert_eq!(p.authenticate(&h).await, AuthOutcome::Authenticated);
    }

    // Basic auth fallback when Google headers are absent
    #[tokio::test]
    async fn basic_auth_falls_through_to_default_when_no_google_headers() {
        let p = make_provider("chan-id", "chan-tok", Some("user"), Some("pass"));
        let creds = format!("Basic {}", basic_b64("user", "pass"));
        let h = headers_with(&[("Authorization", &creds)]);
        assert_eq!(p.authenticate(&h).await, AuthOutcome::Authenticated);
    }
}
