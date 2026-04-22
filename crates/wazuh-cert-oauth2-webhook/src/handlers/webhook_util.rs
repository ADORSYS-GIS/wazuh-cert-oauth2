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

#[cfg(test)]
mod tests {
    use super::extract_user_id;
    use crate::models::WebhookRequest;
    use std::collections::HashMap;

    fn request_with(resource_path: Option<&str>, representation: Option<&str>) -> WebhookRequest {
        WebhookRequest {
            event_type: "user-update".to_string(),
            realm_id: "realm-a".to_string(),
            id: None,
            time: None,
            client_id: None,
            ip_address: None,
            error: None,
            details: Some(HashMap::new()),
            resource_path: resource_path.map(|v| v.to_string()),
            representation: representation.map(|v| v.to_string()),
        }
    }

    #[test]
    fn prefers_id_from_representation_when_present() {
        let req = request_with(
            Some("users/path-id"),
            Some(r#"{"id":"representation-id","enabled":true,"username":"u","email":"u@x"}"#),
        );

        assert_eq!(
            extract_user_id(&req).as_deref(),
            Some("representation-id")
        );
    }

    #[test]
    fn falls_back_to_resource_path_when_representation_missing() {
        let req = request_with(Some("admin/realms/a/users/resource-id"), None);
        assert_eq!(extract_user_id(&req).as_deref(), Some("resource-id"));
    }

    #[test]
    fn returns_none_when_no_source_contains_user_id() {
        let req = request_with(Some("admin/realms/a/groups/abc"), None);
        assert_eq!(extract_user_id(&req), None);
    }
}
