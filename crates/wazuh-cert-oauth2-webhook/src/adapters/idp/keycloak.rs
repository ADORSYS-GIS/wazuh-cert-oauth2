use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, from_value};
use std::collections::HashMap;
use tracing::{debug, info};
use wazuh_cert_oauth2_model::models::errors::{AppError, AppResult};
use wazuh_cert_oauth2_model::services::http_client::HttpClient;

use crate::models::SimpleUserRepresentation;
use crate::opts::Opt;
use crate::ports::idp::{IdpEvent, IdpProvider, IdpUser};

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct KeycloakWebhookRequest {
    #[serde(rename = "type")]
    pub event_type: String,

    #[serde(rename = "realmId")]
    pub realm_id: String,

    pub id: Option<String>,

    pub time: Option<f64>,

    #[serde(rename = "clientId")]
    pub client_id: Option<String>,

    #[serde(rename = "ipAddress")]
    pub ip_address: Option<String>,

    pub error: Option<String>,

    pub details: Option<HashMap<String, JsonValue>>,

    #[serde(rename = "resourcePath")]
    pub resource_path: Option<String>,

    pub representation: Option<String>,
}

/// Keycloak IdP adapter.
#[derive(Clone)]
pub struct KeycloakAdapter {
    pub admin_base_url: Option<String>,
    pub revoke_reason: String,
    pub http: HttpClient,
}

impl KeycloakAdapter {
    pub fn from_opt(opt: &Opt, http: HttpClient) -> Self {
        let admin_base_url = opt
            .idp_admin_base_url
            .clone()
            .or_else(|| Some("https://keycloak.wazuh.com/auth/admin/realms/wazuh".to_string()));
        let revoke_reason = opt
            .idp_revoke_reason
            .clone()
            .unwrap_or_else(|| "Keycloak event".to_string());

        Self {
            admin_base_url,
            revoke_reason,
            http,
        }
    }
}

#[async_trait]
impl IdpProvider for KeycloakAdapter {
    fn parse_event(&self, raw: &serde_json::Value) -> IdpEvent {
        let req: KeycloakWebhookRequest = match from_value(raw.clone()) {
            Ok(v) => v,
            Err(_) => return IdpEvent::Ignore,
        };

        let t = req.event_type.to_ascii_lowercase();

        if t == "user-delete" {
            if let Some(rp) = &req.resource_path
                && !rp.contains("users/")
            {
                return IdpEvent::Ignore;
            }

            let subject = extract_subject_from_request(&req);
            match subject {
                Some(sub) => return IdpEvent::UserRevoke { subject: sub },
                None => {
                    tracing::warn!(
                        "Keycloak user-delete event missing subject; ignoring. \
                         resource_path={:?}",
                        req.resource_path
                    );
                    return IdpEvent::Ignore;
                }
            }
        }

        if t == "user-update" {
            if let Some(rp) = &req.resource_path
                && !rp.contains("users/")
            {
                return IdpEvent::Ignore;
            }

            if let Some(rep_str) = &req.representation
                && let Ok(rep) = serde_json::from_str::<SimpleUserRepresentation>(rep_str)
                && !rep.enabled
            {
                let subject = extract_subject_from_request(&req);
                match subject {
                    Some(sub) => return IdpEvent::UserRevoke { subject: sub },
                    None => {
                        tracing::warn!(
                            "Keycloak user-update (disabled) event missing subject; ignoring. \
                             resource_path={:?}",
                            req.resource_path
                        );
                        return IdpEvent::Ignore;
                    }
                }
            }
            return IdpEvent::Ignore;
        }

        if t == "register" || t == "user-create" {
            return IdpEvent::UserCreate {
                event_type: req.event_type,
            };
        }

        IdpEvent::Ignore
    }

    fn extract_user(&self, raw: &serde_json::Value) -> AppResult<SimpleUserRepresentation> {
        let req: KeycloakWebhookRequest = from_value(raw.clone())
            .map_err(|e| AppError::Serialization(format!("Keycloak webhook parse error: {}", e)))?;

        match &req.representation {
            None => Err(AppError::Serialization(
                "Webhook missing representation".to_string(),
            )),
            Some(rep) => serde_json::from_str::<SimpleUserRepresentation>(rep).map_err(|e| {
                AppError::Serialization(format!("Keycloak user representation parse error: {}", e))
            }),
        }
    }

    async fn fetch_users(&self, access_token: &str) -> AppResult<Vec<IdpUser>> {
        let admin_url = self.admin_base_url.as_ref().ok_or_else(|| {
            AppError::UpstreamError(
                "IDP_ADMIN_BASE_URL not configured. This is required for enrollment auditing."
                    .to_string(),
            )
        })?;

        let users_url = format!("{}/users?max=5000", admin_url.trim_end_matches('/'));
        debug!("Fetching users from Keycloak: {}", users_url);

        let raw: Vec<RawKeycloakUser> = self.http.fetch_json_auth(&users_url, access_token).await?;

        let users = raw
            .into_iter()
            .map(|u| IdpUser {
                id: u.id,
                username: u.username,
                email: u.email,
                enabled: u.enabled,
            })
            .collect();

        info!("Fetched Keycloak users");
        Ok(users)
    }

    fn revoke_reason(&self) -> String {
        self.revoke_reason.clone()
    }
}

/// Raw Keycloak user as returned by the Admin REST API.
#[derive(serde::Deserialize)]
struct RawKeycloakUser {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub enabled: bool,
}

fn extract_subject_from_request(req: &KeycloakWebhookRequest) -> Option<String> {
    if let Some(rep) = &req.representation
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(rep)
        && let Some(id) = v.get("id").and_then(|x| x.as_str())
    {
        return Some(id.to_string());
    }

    if let Some(details) = &req.details
        && let Some(v) = details.get("userId").and_then(|x| x.as_str())
    {
        return Some(v.to_string());
    }

    if let Some(rp) = &req.resource_path {
        let parts: Vec<&str> = rp.split('/').collect();
        if let Some(pos) = parts.iter().position(|&s| s == "users")
            && let Some(id) = parts.get(pos + 1)
            && !id.is_empty()
        {
            return Some(id.to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_adapter() -> KeycloakAdapter {
        KeycloakAdapter {
            admin_base_url: Some("http://keycloak/admin/realms/dev".to_string()),
            revoke_reason: "Keycloak event".to_string(),
            http: HttpClient::new_with_defaults().unwrap(),
        }
    }

    #[test]
    fn parse_event_user_delete_with_user_path_returns_revoke() {
        let adapter = make_adapter();
        let payload = json!({
            "type": "user-delete",
            "realmId": "realm",
            "resourcePath": "admin/realms/x/users/uuid-123",
            "representation": "{\"id\":\"uuid-123\",\"enabled\":false,\"username\":\"bob\"}"
        });
        assert_eq!(
            adapter.parse_event(&payload),
            IdpEvent::UserRevoke {
                subject: "uuid-123".to_string()
            }
        );
    }

    #[test]
    fn parse_event_user_update_disabled_returns_revoke() {
        let adapter = make_adapter();
        let payload = json!({
            "type": "user-update",
            "realmId": "realm",
            "resourcePath": "admin/realms/x/users/uuid-123",
            "representation": "{\"id\":\"uuid-123\",\"enabled\":false,\"username\":\"bob\"}"
        });
        assert_eq!(
            adapter.parse_event(&payload),
            IdpEvent::UserRevoke {
                subject: "uuid-123".to_string()
            }
        );
    }

    #[test]
    fn parse_event_user_update_active_returns_ignore() {
        let adapter = make_adapter();
        let payload = json!({
            "type": "user-update",
            "realmId": "realm",
            "resourcePath": "admin/realms/x/users/uuid-123",
            "representation": "{\"id\":\"uuid-123\",\"enabled\":true,\"username\":\"bob\"}"
        });
        assert_eq!(adapter.parse_event(&payload), IdpEvent::Ignore);
    }

    #[test]
    fn extract_user_works() {
        let adapter = make_adapter();
        let payload = json!({
            "type": "user-create",
            "realmId": "realm",
            "representation": "{\"id\":\"user-1\",\"enabled\":false,\"username\":\"alice\",\"email\":\"a@example.com\"}"
        });
        let user = adapter.extract_user(&payload).unwrap();
        assert_eq!(user.id, Some("user-1".to_string()));
        assert_eq!(user.username, Some("alice".to_string()));
    }
}
