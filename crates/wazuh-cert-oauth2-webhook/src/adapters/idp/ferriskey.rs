use async_trait::async_trait;
use serde::Deserialize;
use serde_json::from_value;
use wazuh_cert_oauth2_model::models::errors::{AppError, AppResult};
use wazuh_cert_oauth2_model::services::http_client::HttpClient;

use crate::models::SimpleUserRepresentation;
use crate::ports::idp::{IdpEvent, IdpProvider, IdpUser};

#[derive(Deserialize, Debug, Clone)]
pub struct FerriskeyWebhookRequest {
    pub event: String,
    pub resource_id: String,
    pub data: Option<FerriskeyUserData>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct FerriskeyUserData {
    pub username: String,
    pub email: String,
    pub firstname: Option<String>,
    pub lastname: Option<String>,
    pub enabled: bool,
}

/// Ferriskey IdP adapter.
#[derive(Clone)]
pub struct FerriskeyAdapter {
    pub admin_base_url: Option<String>,
    pub revoke_reason: String,
    pub http: HttpClient,
}

impl FerriskeyAdapter {
    pub fn from_opt(
        admin_base_url: Option<String>,
        revoke_reason: Option<String>,
        http: HttpClient,
    ) -> Self {
        Self {
            admin_base_url,
            revoke_reason: revoke_reason.unwrap_or_else(|| "Ferriskey event".to_string()),
            http,
        }
    }
}

#[async_trait]
impl IdpProvider for FerriskeyAdapter {
    fn parse_event(&self, raw: &serde_json::Value) -> IdpEvent {
        let f: FerriskeyWebhookRequest = match from_value(raw.clone()) {
            Ok(v) => v,
            Err(_) => return IdpEvent::Ignore,
        };

        match f.event.as_str() {
            "user.deleted" => IdpEvent::UserRevoke {
                subject: f.resource_id,
            },
            "user.updated" => {
                if let Some(data) = f.data
                    && !data.enabled
                {
                    IdpEvent::UserRevoke {
                        subject: f.resource_id,
                    }
                } else {
                    IdpEvent::Ignore
                }
            }
            "user.created" => IdpEvent::UserCreate {
                event_type: f.event,
            },
            _ => IdpEvent::Ignore,
        }
    }

    fn extract_user(&self, raw: &serde_json::Value) -> AppResult<SimpleUserRepresentation> {
        let f: FerriskeyWebhookRequest = from_value(raw.clone()).map_err(|e| {
            AppError::Serialization(format!("Ferriskey webhook parse error: {}", e))
        })?;

        let data = f
            .data
            .ok_or_else(|| AppError::Serialization("Ferriskey webhook missing data".to_string()))?;

        Ok(SimpleUserRepresentation {
            id: Some(f.resource_id),
            enabled: data.enabled,
            username: Some(data.username),
            email: Some(data.email),
            first_name: data.firstname,
            last_name: data.lastname,
        })
    }

    async fn fetch_users(&self, access_token: &str) -> AppResult<Vec<IdpUser>> {
        let admin_url = self.admin_base_url.as_ref().ok_or_else(|| {
            AppError::UpstreamError(
                "IDP_ADMIN_BASE_URL not configured for Ferriskey adapter.".to_string(),
            )
        })?;

        let users_url = format!("{}/users", admin_url.trim_end_matches('/'));
        let users: Vec<IdpUser> = self.http.fetch_json_auth(&users_url, access_token).await?;
        Ok(users)
    }

    fn revoke_reason(&self) -> String {
        self.revoke_reason.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_adapter() -> FerriskeyAdapter {
        FerriskeyAdapter::from_opt(
            Some("http://ferriskey/api/admin/realms/dev".to_string()),
            None,
            HttpClient::new_with_defaults().unwrap(),
        )
    }

    #[test]
    fn parse_event_user_deleted_returns_revoke() {
        let adapter = make_adapter();
        let payload = json!({
            "event": "user.deleted",
            "timestamp": "now",
            "resource_id": "uuid-123",
            "data": null
        });

        assert_eq!(
            adapter.parse_event(&payload),
            IdpEvent::UserRevoke {
                subject: "uuid-123".to_string()
            }
        );
    }

    #[test]
    fn parse_event_user_updated_disabled_returns_revoke() {
        let adapter = make_adapter();
        let payload = json!({
            "event": "user.updated",
            "timestamp": "now",
            "resource_id": "uuid-123",
            "data": {
                "username": "bob",
                "email": "bob@x.com",
                "enabled": false,
                "email_verified": true
            }
        });

        assert_eq!(
            adapter.parse_event(&payload),
            IdpEvent::UserRevoke {
                subject: "uuid-123".to_string()
            }
        );
    }

    #[test]
    fn parse_event_user_updated_active_returns_ignore() {
        let adapter = make_adapter();
        let payload = json!({
            "event": "user.updated",
            "timestamp": "now",
            "resource_id": "uuid-123",
            "data": {
                "username": "bob",
                "email": "bob@x.com",
                "enabled": true,
                "email_verified": true
            }
        });

        assert_eq!(adapter.parse_event(&payload), IdpEvent::Ignore);
    }

    #[test]
    fn parse_event_user_created_returns_create() {
        let adapter = make_adapter();
        let payload = json!({
            "event": "user.created",
            "timestamp": "now",
            "resource_id": "uuid-123",
            "data": null
        });

        assert_eq!(
            adapter.parse_event(&payload),
            IdpEvent::UserCreate {
                event_type: "user.created".to_string()
            }
        );
    }

    #[test]
    fn extract_user_works() {
        let adapter = make_adapter();
        let payload = json!({
            "event": "user.updated",
            "timestamp": "now",
            "resource_id": "uuid-123",
            "data": {
                "username": "bob",
                "email": "bob@x.com",
                "enabled": true,
                "email_verified": true
            }
        });

        let user = adapter.extract_user(&payload).unwrap();
        assert_eq!(user.id, Some("uuid-123".to_string()));
        assert_eq!(user.username, Some("bob".to_string()));
        assert!(user.enabled);
    }
}
