use crate::handlers::middle::JwtToken;
use crate::models::ca_config::CaProvider;
use crate::shared::certs::sign_csr;
use crate::shared::ledger::Ledger;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::State;
use tracing::{debug, error, info};
use wazuh_cert_oauth2_model::models::errors::AppError;
use wazuh_cert_oauth2_model::models::sign_csr_request::SignCsrRequest;
use wazuh_cert_oauth2_model::models::signed_cert_response::SignedCertResponse;

/// Sign a CSR for a new agent using the issuing CA
/// Expects a PKCS#10 CSR in PEM format; returns the signed certificate and CA cert
#[post("/register-agent", format = "application/json", data = "<dto>")]
#[tracing::instrument(skip(dto, token, config, ledger), fields(sub = %token.claims.sub))]
pub async fn register_agent(
    dto: Json<SignCsrRequest>,
    token: JwtToken,
    config: &State<CaProvider>,
    ledger: &State<Ledger>,
) -> anyhow::Result<Json<SignedCertResponse>, Status> {
    info!(
        "POST /register-agent called for subject={}",
        token.claims.sub
    );
    debug!("CSR payload received (not logging PEM contents)");
    match sign_csr(dto.into_inner(), token, config.inner(), ledger.inner()).await {
        Ok(res) => Ok(Json(res)),
        Err(e) => {
            error!("CSR signing failed: {}", e);
            match e {
                AppError::CsrMissingPublicKey
                | AppError::CsrVerificationFailed
                | AppError::KeyPolicyRsaTooSmall { .. }
                | AppError::KeyPolicyUnsupportedEcCurve { .. }
                | AppError::KeyPolicyUnknownEcCurve
                | AppError::KeyPolicyUnsupportedKeyType { .. } => Err(Status::BadRequest),
                _ => Err(Status::InternalServerError),
            }
        }
    }
}
