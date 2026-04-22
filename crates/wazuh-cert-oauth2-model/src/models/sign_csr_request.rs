use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct SignCsrRequest {
    pub csr_pem: String,
}

#[cfg(test)]
mod tests {
    use super::SignCsrRequest;

    #[test]
    fn sign_csr_request_round_trip() {
        let req = SignCsrRequest {
            csr_pem: "-----BEGIN CERTIFICATE REQUEST-----...".to_string(),
        };

        let json = serde_json::to_string(&req).expect("serialize should work");
        let parsed: SignCsrRequest = serde_json::from_str(&json).expect("parse should work");
        assert_eq!(parsed.csr_pem, req.csr_pem);
    }
}
