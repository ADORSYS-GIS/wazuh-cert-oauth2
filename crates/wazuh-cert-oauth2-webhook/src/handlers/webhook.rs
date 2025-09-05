use log::{info, warn};
use rocket::State;
use rocket::http::Status;
use rocket::serde::json::Json;
use serde::Deserialize;
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use wazuh_cert_oauth2_model::models::revoke_request::RevokeRequest;

use crate::handlers::auth::WebhookAuth;
use crate::state::ProxyState;

#[derive(Deserialize, Debug)]
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

#[post("/", format = "application/json", data = "<payload>")]
pub async fn send_webhook(
    _auth: WebhookAuth,
    state: &State<ProxyState>,
    payload: Json<WebhookRequest>,
) -> Result<Status, Status> {
    let p = payload.into_inner();
    let et_lower = p.event_type.to_ascii_lowercase();

    if !state.is_allowed_event(&et_lower, p.resource_path.as_deref()) {
        info!(
            "ignored webhook event type={} resourcePath={:?}",
            p.event_type, p.resource_path
        );
        return Ok(Status::Ok);
    }

    let subject = extract_user_id(&p);
    if subject.is_none() {
        warn!(
            "webhook event missing userId; type={} details={:?} resource={:?}",
            p.event_type, p.details, p.resource_path
        );
        return Ok(Status::Ok);
    }
    let subject = subject.unwrap();

    let req = RevokeRequest {
        serial_hex: None,
        subject: Some(subject),
        reason: state.revoke_reason(),
    };

    match state.forward_revoke_with_retry(req.clone()).await {
        Ok(()) => Ok(Status::Ok),
        Err(e) => {
            warn!("immediate forward failed: {} — queueing", e);
            state
                .queue_revoke(req)
                .await
                .map(|_| Status::Ok)
                .map_err(|_| Status::InternalServerError)
        }
    }
}

fn extract_user_id(p: &WebhookRequest) -> Option<String> {
    if let Some(u) = &p.user_id {
        return Some(u.clone());
    }
    if let Some(details) = &p.details {
        if let Some(JsonValue::String(s)) = details.get("userId") {
            return Some(s.clone());
        }
        if let Some(JsonValue::String(s)) = details.get("user_id") {
            return Some(s.clone());
        }
        if let Some(JsonValue::String(s)) = details.get("id") {
            return Some(s.clone());
        }
    }
    if let Some(rp) = &p.resource_path {
        if let Some(idx) = rp.find("users/") {
            let rest = &rp[idx + 6..];
            let id_end = rest.find('/').unwrap_or(rest.len());
            let id = &rest[..id_end];
            if !id.is_empty() {
                return Some(id.to_string());
            }
        }
    }
    None
}
