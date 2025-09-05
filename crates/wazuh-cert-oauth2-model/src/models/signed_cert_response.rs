use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct SignedCertResponse {
    pub certificate_pem: String,
    pub ca_cert_pem: String,
}
