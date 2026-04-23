use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct SignedCertResponse {
    pub certificate_pem: String,
    pub ca_cert_pem: String,
}

#[cfg(test)]
mod tests {
    use super::SignedCertResponse;

    #[test]
    fn signed_cert_response_round_trip() {
        let response = SignedCertResponse {
            certificate_pem: "CERT".to_string(),
            ca_cert_pem: "CA".to_string(),
        };
        let json = serde_json::to_string(&response).expect("serialize should work");
        let parsed: SignedCertResponse = serde_json::from_str(&json).expect("parse should work");
        assert_eq!(parsed.certificate_pem, "CERT");
        assert_eq!(parsed.ca_cert_pem, "CA");
    }
}
