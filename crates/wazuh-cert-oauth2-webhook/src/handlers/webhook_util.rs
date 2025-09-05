use serde_json::Value as JsonValue;

use crate::models::WebhookRequest;

#[inline]
pub(super) fn extract_user_id(p: &WebhookRequest) -> Option<String> {
    if let Some(u) = &p.user_id { return Some(u.clone()); }
    if let Some(details) = &p.details {
        if let Some(JsonValue::String(s)) = details.get("userId") { return Some(s.clone()); }
        if let Some(JsonValue::String(s)) = details.get("user_id") { return Some(s.clone()); }
        if let Some(JsonValue::String(s)) = details.get("id") { return Some(s.clone()); }
    }
    if let Some(rp) = &p.resource_path
        && let Some(idx) = rp.find("users/") {
        let rest = &rp[idx + 6..];
        let id_end = rest.find('/').unwrap_or(rest.len());
        let id = &rest[..id_end];
        if !id.is_empty() { return Some(id.to_string()); }
    }
    None
}

