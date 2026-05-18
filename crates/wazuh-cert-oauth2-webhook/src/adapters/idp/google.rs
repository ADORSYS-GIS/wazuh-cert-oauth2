use async_trait::async_trait;
use serde::Deserialize;
use tracing::{info, warn};
use wazuh_cert_oauth2_model::models::errors::{AppError, AppResult};
use wazuh_cert_oauth2_model::services::http_client::HttpClient;

use crate::models::SimpleUserRepresentation;
use crate::ports::idp::{IdpEvent, IdpProvider, IdpUser};

/// Google Workspace Directory API adapter.
#[derive(Clone)]
pub struct GoogleIdpAdapter {
    pub admin_base_url: String,
    pub customer: Option<String>,
    pub domain: Option<String>,
    pub revoke_reason: String,
    pub http: HttpClient,
}

#[async_trait]
impl IdpProvider for GoogleIdpAdapter {
    fn parse_event(&self, _raw: &serde_json::Value) -> IdpEvent {
        warn!("Google IdP parse_event called without headers; body-only parsing not supported.");
        IdpEvent::Ignore
    }

    fn parse_event_with_headers(
        &self,
        headers: &rocket::http::HeaderMap<'_>,
        body: &serde_json::Value,
    ) -> IdpEvent {
        // Google push notifications use X-Goog-Resource-State header
        let state = match headers.get_one("X-Goog-Resource-State") {
            Some(s) => s,
            None => {
                warn!("Google webhook missing X-Goog-Resource-State header; ignoring.");
                return IdpEvent::Ignore;
            }
        };

        match state {
            "sync" => {
                info!("Google webhook sync event received.");
                IdpEvent::Ignore
            }
            "add" => {
                let _id = body.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");
                IdpEvent::UserCreate {
                    event_type: "add".to_string(),
                }
            }
            "delete" => {
                let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
                if id.is_empty() {
                    warn!("Google delete event missing user ID in body: {}", body);
                    IdpEvent::Ignore
                } else {
                    IdpEvent::UserRevoke {
                        subject: id.to_string(),
                    }
                }
            }
            "update" => {
                let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let suspended = body
                    .get("suspended")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                if !id.is_empty() && suspended {
                    IdpEvent::UserRevoke {
                        subject: id.to_string(),
                    }
                } else {
                    IdpEvent::Ignore
                }
            }
            "makeAdmin" | "undelete" => IdpEvent::Ignore,
            _ => {
                warn!("Unhandled Google resource state: {}", state);
                IdpEvent::Ignore
            }
        }
    }

    fn extract_user(&self, raw: &serde_json::Value) -> AppResult<SimpleUserRepresentation> {
        let id = raw["id"]
            .as_str()
            .ok_or_else(|| AppError::Serialization("Google body missing 'id'".to_string()))?;
        let email = raw["primaryEmail"].as_str().ok_or_else(|| {
            AppError::Serialization("Google body missing 'primaryEmail'".to_string())
        })?;

        // Derive username from email local part
        let username = email.split('@').next().unwrap_or(email);

        Ok(SimpleUserRepresentation {
            id: Some(id.to_string()),
            username: Some(username.to_string()),
            email: Some(email.to_string()),
            enabled: true, // Google push events only fire for active/actioned users
            first_name: None,
            last_name: None,
        })
    }

    async fn fetch_users(&self, access_token: &str) -> AppResult<Vec<IdpUser>> {
        let scope_param = if let Some(domain) = &self.domain {
            format!("domain={}", domain)
        } else if let Some(customer) = &self.customer {
            format!("customer={}", customer)
        } else {
            return Err(AppError::Configuration(
                "GoogleIdpAdapter requires either GOOGLE_DOMAIN or GOOGLE_CUSTOMER to be set"
                    .into(),
            ));
        };

        let mut all_users = Vec::new();
        let mut page_token: Option<String> = None;

        loop {
            let mut url = format!(
                "{}/users?{}&maxResults=500",
                self.admin_base_url.trim_end_matches('/'),
                scope_param
            );
            if let Some(token) = &page_token {
                url.push_str(&format!("&pageToken={}", token));
            }

            let page: GoogleUsersPage = self.http.fetch_json_auth(&url, access_token).await?;

            if let Some(users) = page.users {
                for u in users {
                    all_users.push(IdpUser {
                        id: u.id,
                        username: u
                            .primary_email
                            .split('@')
                            .next()
                            .unwrap_or(&u.primary_email)
                            .to_string(),
                        email: Some(u.primary_email),
                        enabled: !u.suspended.unwrap_or(false),
                    });
                }
            }

            page_token = page.next_page_token;
            if page_token.is_none() {
                break;
            }
        }

        Ok(all_users)
    }

    fn revoke_reason(&self) -> String {
        self.revoke_reason.clone()
    }
}

#[derive(Deserialize)]
struct GoogleUsersPage {
    users: Option<Vec<GoogleUser>>,
    #[serde(rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct GoogleUser {
    id: String,
    #[serde(rename = "primaryEmail")]
    primary_email: String,
    suspended: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocket::http::HeaderMap;
    use serde_json::json;

    fn make_adapter() -> GoogleIdpAdapter {
        GoogleIdpAdapter {
            admin_base_url: "https://admin.googleapis.com/admin/directory/v1".to_string(),
            customer: Some("my_customer".to_string()),
            domain: None,
            revoke_reason: "Google Workspace event".to_string(),
            http: HttpClient::new_with_defaults().unwrap(),
        }
    }

    #[test]
    fn sync_resource_state_returns_ignore() {
        let adapter = make_adapter();
        let mut headers = HeaderMap::new();
        headers.add_raw("X-Goog-Resource-State", "sync");
        let body = json!({});
        assert_eq!(
            adapter.parse_event_with_headers(&headers, &body),
            IdpEvent::Ignore
        );
    }

    #[test]
    fn add_resource_state_returns_user_create() {
        let adapter = make_adapter();
        let mut headers = HeaderMap::new();
        headers.add_raw("X-Goog-Resource-State", "add");
        let body = json!({"id": "123"});
        assert_eq!(
            adapter.parse_event_with_headers(&headers, &body),
            IdpEvent::UserCreate {
                event_type: "add".to_string()
            }
        );
    }

    #[test]
    fn delete_resource_state_returns_user_revoke() {
        let adapter = make_adapter();
        let mut headers = HeaderMap::new();
        headers.add_raw("X-Goog-Resource-State", "delete");
        let body = json!({"id": "uuid-123"});
        assert_eq!(
            adapter.parse_event_with_headers(&headers, &body),
            IdpEvent::UserRevoke {
                subject: "uuid-123".to_string()
            }
        );
    }

    #[test]
    fn update_resource_state_suspended_returns_user_revoke() {
        let adapter = make_adapter();
        let mut headers = HeaderMap::new();
        headers.add_raw("X-Goog-Resource-State", "update");
        let body = json!({
            "id": "uuid-123",
            "suspended": true
        });
        assert_eq!(
            adapter.parse_event_with_headers(&headers, &body),
            IdpEvent::UserRevoke {
                subject: "uuid-123".to_string()
            }
        );
    }

    #[test]
    fn update_resource_state_active_returns_ignore() {
        let adapter = make_adapter();
        let mut headers = HeaderMap::new();
        headers.add_raw("X-Goog-Resource-State", "update");
        let body = json!({
            "id": "uuid-123",
            "suspended": false
        });
        assert_eq!(
            adapter.parse_event_with_headers(&headers, &body),
            IdpEvent::Ignore
        );
    }

    #[test]
    fn missing_resource_state_header_returns_ignore() {
        let adapter = make_adapter();
        let headers = HeaderMap::new();
        let body = json!({});
        assert_eq!(
            adapter.parse_event_with_headers(&headers, &body),
            IdpEvent::Ignore
        );
    }

    #[test]
    fn extract_user_maps_primary_email_to_email_field() {
        let adapter = make_adapter();
        let body = json!({
            "id": "111",
            "primaryEmail": "alice@example.com"
        });
        let user = adapter.extract_user(&body).unwrap();
        assert_eq!(user.id, Some("111".to_string()));
        assert_eq!(user.email, Some("alice@example.com".to_string()));
        assert_eq!(user.username, Some("alice".to_string()));
    }
}
