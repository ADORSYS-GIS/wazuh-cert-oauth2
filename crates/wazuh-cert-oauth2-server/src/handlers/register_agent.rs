use crate::handlers::middle::JwtToken;
use crate::models::ca_config::CaProvider;
use crate::shared::certs::sign_csr;
use crate::shared::ledger::Ledger;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::State;
use wazuh_cert_oauth2_model::models::sign_csr_request::SignCsrRequest;
use wazuh_cert_oauth2_model::models::signed_cert_response::SignedCertResponse;
use wazuh_cert_oauth2_model::models::errors::AppError;

/// Sign a CSR for a new agent using the issuing CA
/// Expects a PKCS#10 CSR in PEM format; returns the signed certificate and CA cert
#[post("/register-agent", format = "application/json", data = "<dto>")]
pub async fn register_agent(
    dto: Json<SignCsrRequest>,
    token: JwtToken,
    config: &State<CaProvider>,
    ledger: &State<Ledger>,
) -> Result<Json<SignedCertResponse>, Status> {
    match sign_csr(dto.into_inner(), token, config.inner(), ledger.inner()).await {
        Ok(res) => Ok(Json(res)),
        Err(e) => {
            error!("CSR signing failed: {}", e);
            // Try to map underlying AppError to a proper status code
            if let Some(app) = e.downcast_ref::<AppError>() {
                match app {
                    AppError::CsrMissingPublicKey
                    | AppError::CsrVerificationFailed
                    | AppError::KeyPolicyRsaTooSmall { .. }
                    | AppError::KeyPolicyUnsupportedEcCurve { .. }
                    | AppError::KeyPolicyUnknownEcCurve
                    | AppError::KeyPolicyUnsupportedKeyType { .. } => Err(Status::BadRequest),
                    _ => Err(Status::InternalServerError),
                }
            } else {
                Err(Status::InternalServerError)
            }
        }
    }
}
