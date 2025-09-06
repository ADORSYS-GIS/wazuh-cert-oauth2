use crate::models::{SimpleUserRepresentation, WebhookRequest};

pub(super) fn extract_user_id(p: &WebhookRequest) -> Option<String> {
    if let Ok(SimpleUserRepresentation { id, .. }) = &p.get_simple_user_representation() {
        return Some(id.to_string());
    }

    if let Some(rp) = &p.resource_path
        && let Some(idx) = rp.find("users/")
    {
        let rest = &rp[idx + 6..];
        let id_end = rest.find('/').unwrap_or(rest.len());
        let id = &rest[..id_end];
        if !id.is_empty() {
            return Some(id.to_string());
        }
    }
    None
}
