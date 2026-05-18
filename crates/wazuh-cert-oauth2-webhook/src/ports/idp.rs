use crate::models::SimpleUserRepresentation;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use wazuh_cert_oauth2_model::models::errors::AppResult;

/// A Keycloak/IdP user returned by the admin API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpUser {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub enabled: bool,
}

/// Parsed IdP webhook event.
///
/// - UserRevoke: User updated or deleted — revoke their certificate.
/// - UserCreate: User registered / created — open a GitHub ticket.
/// - Ignore: Ignore the event.
#[derive(Debug, Clone, PartialEq)]
pub enum IdpEvent {
    UserRevoke { subject: String },
    UserCreate { event_type: String },
    Ignore,
}

/// Port: Identity Provider capabilities needed by the webhook crate.
#[async_trait]
pub trait IdpProvider: Send + Sync {
    fn parse_event(&self, raw: &serde_json::Value) -> IdpEvent;

    /// Parse a raw JSON body and headers into an `IdpEvent`.
    /// Google Workspace sends the event type in headers.
    fn parse_event_with_headers(
        &self,
        _headers: &rocket::http::HeaderMap<'_>,
        body: &serde_json::Value,
    ) -> IdpEvent {
        self.parse_event(body)
    }

    fn extract_user(&self, raw: &serde_json::Value) -> AppResult<SimpleUserRepresentation>;

    /// Fetch all enabled users from the IdP admin API.
    async fn fetch_users(&self, access_token: &str) -> AppResult<Vec<IdpUser>>;

    fn revoke_reason(&self) -> String;
}
