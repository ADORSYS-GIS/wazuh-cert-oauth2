use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct SignCsrRequest {
    pub csr_pem: String,
    #[serde(default)]
    pub overwrite: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::SignCsrRequest;

    #[test]
    fn sign_csr_request_round_trip() {
        let req = SignCsrRequest {
            csr_pem: "-----BEGIN CERTIFICATE REQUEST-----...".to_string(),
            overwrite: Some(true),
        };

        let json = serde_json::to_string(&req).expect("serialize should work");
        let parsed: SignCsrRequest = serde_json::from_str(&json).expect("parse should work");
        assert_eq!(parsed.csr_pem, req.csr_pem);
    }

    #[test]
    fn overwrite_defaults_to_none_when_field_absent() {
        // Older clients or raw API calls that omit the field must not fail deserialization
        let json = r#"{"csr_pem":"-----BEGIN CERTIFICATE REQUEST-----..."}"#;
        let parsed: SignCsrRequest = serde_json::from_str(json).expect("parse should work");
        assert_eq!(parsed.overwrite, None);
    }
}
