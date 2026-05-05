use crate::handlers::middle::JwtToken;
use crate::models::ca_config::CaProvider;
use crate::shared::certs::sign_csr;
use crate::shared::crl::CrlState;
use crate::shared::ledger::Ledger;
use crate::shared::webhook_notifier::WebhookNotifier;
use rocket::State;
use rocket::serde::json::Json;
use tracing::{debug, error, info};
use wazuh_cert_oauth2_model::models::errors::AppError;
use wazuh_cert_oauth2_model::models::sign_csr_request::SignCsrRequest;
use wazuh_cert_oauth2_model::models::signed_cert_response::SignedCertResponse;

/// Sign a CSR for a new agent using the issuing CA
/// Expects a PKCS#10 CSR in PEM format; returns the signed certificate and CA cert
#[post("/register-agent", format = "application/json", data = "<dto>")]
#[tracing::instrument(skip(dto, token, config, ledger, crl, webhook), fields(sub = %token.claims.sub))]
pub async fn register_agent(
    dto: Json<SignCsrRequest>,
    token: JwtToken,
    config: &State<CaProvider>,
    ledger: &State<Ledger>,
    crl: &State<CrlState>,
    webhook: &State<Option<WebhookNotifier>>,
) -> Result<Json<SignedCertResponse>, AppError> {
    info!(
        "POST /register-agent called for subject={}",
        token.claims.sub
    );
    debug!("CSR payload received (not logging PEM contents)");
    match sign_csr(
        dto.into_inner(),
        token,
        config.inner(),
        ledger.inner(),
        crl.inner(),
        webhook.inner().as_ref(),
    )
    .await
    {
        Ok(res) => Ok(Json(res)),
        Err(e) => {
            error!("CSR signing failed: {}", e);
            Err(e)
        }
    }
}
