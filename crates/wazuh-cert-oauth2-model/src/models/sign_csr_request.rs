use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct SignCsrRequest {
    pub csr_pem: String,
}
