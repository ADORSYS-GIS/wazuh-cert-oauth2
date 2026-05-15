use crate::models::{SimpleUserRepresentation, WebhookRequest};

pub(super) fn extract_user_id(p: &WebhookRequest) -> Option<String> {
    if let Ok(SimpleUserRepresentation { id: Some(id), .. }) = &p.get_simple_user_representation() {
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

pub fn prepare_github_issue(p: &WebhookRequest) -> (String, String) {
    let user = p.get_simple_user_representation().ok();

    // Extract Email: representation > unknown
    let email = user
        .as_ref()
        .and_then(|u| u.email.clone())
        .unwrap_or_else(|| "unknown".to_string());

    // Extract Username: representation.username > representation.first+last > "unknown"
    let username = user
        .as_ref()
        .and_then(|u| u.username.clone())
        .or_else(|| {
            user.as_ref()
                .and_then(|u| match (&u.first_name, &u.last_name) {
                    (Some(f), Some(l)) => Some(format!("{} {}", f, l)),
                    (Some(f), None) => Some(f.clone()),
                    (None, Some(l)) => Some(l.clone()),
                    (None, None) => None,
                })
        })
        .unwrap_or_else(|| "unknown".to_string());

    let title = format!("New user registered: {}", username);
    let body = format!(
        "A new user has been registered in Keycloak.\n\
        ---\n\n\
         - **Username**: {}\n\
         - **Email**: {}\n\
         - **Realm**: {}",
        username, email, p.realm_id
    );

    (title, body)
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

        assert_eq!(extract_user_id(&req).as_deref(), Some("representation-id"));
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
