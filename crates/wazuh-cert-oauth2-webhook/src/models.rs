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

    #[serde(rename = "userId")]
    pub user_id: Option<String>,

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
pub struct SimpleUserRepresentation {
    pub enabled: bool,
    pub username: String,
    pub email: String,
}
