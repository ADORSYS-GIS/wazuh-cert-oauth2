use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct RevokeRequest {
    pub serial_hex: Option<String>,
    pub subject: Option<String>,
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::RevokeRequest;

    #[test]
    fn revoke_request_serializes_and_deserializes() {
        let req = RevokeRequest {
            serial_hex: Some("ABCD".to_string()),
            subject: Some("user-1".to_string()),
            reason: Some("test".to_string()),
        };

        let json = serde_json::to_string(&req).expect("serialization should work");
        let parsed: RevokeRequest =
            serde_json::from_str(&json).expect("deserialization should work");
        assert_eq!(parsed.serial_hex.as_deref(), Some("ABCD"));
        assert_eq!(parsed.subject.as_deref(), Some("user-1"));
        assert_eq!(parsed.reason.as_deref(), Some("test"));
    }
}
