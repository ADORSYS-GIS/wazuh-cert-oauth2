use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, from_str};
use std::collections::HashMap;
use wazuh_cert_oauth2_model::models::errors::{AppError, AppResult};

#[derive(Serialize)]
pub struct Health {
    pub status: String,
}

impl Health {
    pub fn ok() -> Self {
        Self {
            status: "OK".into(),
        }
    }
}

#[derive(Deserialize, Debug, Serialize, Clone, PartialEq)]
pub struct WebhookRequest {
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

impl WebhookRequest {
    pub fn get_simple_user_representation(&self) -> AppResult<SimpleUserRepresentation> {
        match &self.representation {
            None => Err(AppError::Serialization(
                "Webhook missing representation".to_string(),
            )),
            Some(rep) => {
                let d = from_str::<SimpleUserRepresentation>(rep);
                match d {
                    Ok(v) => Ok(v),
                    Err(e) => Err(AppError::Serialization(format!(
                        "Wrong object passed {}",
                        e
                    ))),
                }
            }
        }
    }
}

#[derive(Deserialize, Debug, Serialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SimpleUserRepresentation {
    pub id: Option<String>,
    pub enabled: bool,
    pub username: Option<String>,
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::{Health, WebhookRequest};
    use std::collections::HashMap;
    use wazuh_cert_oauth2_model::models::errors::AppError;

    fn base_request() -> WebhookRequest {
        WebhookRequest {
            event_type: "user-update".to_string(),
            realm_id: "realm-a".to_string(),
            id: None,
            time: None,
            client_id: None,
            ip_address: None,
            error: None,
            details: Some(HashMap::new()),
            resource_path: Some("users/abc123".to_string()),
            representation: None,
        }
    }

    #[test]
    fn health_ok_returns_ok_status() {
        let health = Health::ok();
        assert_eq!(health.status, "OK");
    }

    #[test]
    fn parses_simple_user_representation_from_json_string() {
        let mut req = base_request();
        req.representation = Some(
            r#"{"id":"user-1","enabled":false,"username":"alice","email":"a@example.com"}"#
                .to_string(),
        );

        let user = req
            .get_simple_user_representation()
            .expect("representation should parse");
        assert_eq!(user.id, Some("user-1".to_string()));
        assert!(!user.enabled);
        assert_eq!(user.username, Some("alice".to_string()));
    }

    #[test]
    fn returns_serialization_error_when_representation_is_missing() {
        let req = base_request();
        let err = req
            .get_simple_user_representation()
            .expect_err("missing representation should error");
        assert!(matches!(err, AppError::Serialization(_)));
    }
}
