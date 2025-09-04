use crate::handlers::middle::JwtToken;
use crate::shared::certs::sign_csr;
use rocket::http::Status;
use rocket::serde::json::Json;
use wazuh_cert_oauth2_model::models::sign_csr_request::SignCsrRequest;
use wazuh_cert_oauth2_model::models::signed_cert_response::SignedCertResponse;

/// Sign a CSR for a new agent using the issuing CA
/// Expects a PKCS#10 CSR in PEM format; returns the signed certificate and CA cert
#[post("/register-agent", format = "application/json", data = "<dto>")]
pub async fn register_agent(
    dto: Json<SignCsrRequest>,
    token: JwtToken,
) -> Result<Json<SignedCertResponse>, Status> {
    match sign_csr(dto.into_inner(), token) {
        Ok(res) => Ok(Json(res)),
        Err(e) => {
            let msg = e.to_string();
            error!("CSR signing failed: {}", msg);
            // Classify some errors as BadRequest, else InternalServerError
            if msg.contains("CSR verification failed")
                || msg.contains("Unsupported key type")
                || msg.contains("Unsupported EC curve")
                || msg.contains("RSA key too small")
            {
                Err(Status::BadRequest)
            } else {
                Err(Status::InternalServerError)
            }
        }
    }
}
