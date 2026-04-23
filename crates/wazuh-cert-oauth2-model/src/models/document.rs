use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,

    #[serde(flatten)]
    pub extra: Value, // to capture additional fields
}

#[cfg(test)]
mod tests {
    use super::DiscoveryDocument;
    use serde_json::json;

    #[test]
    fn deserializes_required_fields_and_captures_extra() {
        let raw = json!({
            "issuer": "https://issuer.example/realms/demo",
            "authorization_endpoint": "https://issuer.example/auth",
            "token_endpoint": "https://issuer.example/token",
            "jwks_uri": "https://issuer.example/jwks",
            "userinfo_endpoint": "https://issuer.example/userinfo"
        });

        let doc: DiscoveryDocument =
            serde_json::from_value(raw).expect("document should deserialize");
        assert_eq!(doc.issuer, "https://issuer.example/realms/demo");
        assert_eq!(doc.authorization_endpoint, "https://issuer.example/auth");
        assert_eq!(
            doc.extra["userinfo_endpoint"],
            "https://issuer.example/userinfo"
        );
    }
}
