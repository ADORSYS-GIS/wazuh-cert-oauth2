use async_trait::async_trait;
use rocket::http::HeaderMap;

/// Outcome of webhook authentication.
///
/// - Authenticated: The webhook is authenticated and should be processed.
/// - Denied: The webhook is not authenticated.
/// - NotApplicable: The webhook is not applicable to this adapter.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthOutcome {
    Authenticated,
    Denied,
    NotApplicable,
}

/// Port: inbound webhook request authentication.
#[async_trait]
pub trait WebhookAuthProvider: Send + Sync {
    async fn authenticate(&self, headers: &HeaderMap<'_>) -> AuthOutcome;
}
