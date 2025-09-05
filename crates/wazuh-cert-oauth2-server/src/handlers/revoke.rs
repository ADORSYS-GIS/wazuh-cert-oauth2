use rocket::State;
use rocket::http::Status;
use rocket::serde::json::Json;

use wazuh_cert_oauth2_model::models::revoke_request::RevokeRequest;

use crate::handlers::middle::JwtToken;
use crate::models::ca_config::CaProvider;
use crate::shared::crl::CrlState;
use crate::shared::ledger::Ledger;
use log::error;

/// Revoke a certificate by serial and optional reason, then rebuild CRL
#[post("/revoke", format = "application/json", data = "<dto>")]
pub async fn revoke(
    _token: JwtToken,
    dto: Json<RevokeRequest>,
    crl: &State<CrlState>,
    ledger: &State<Ledger>,
    ca: &State<CaProvider>,
) -> Result<Status, Status> {
    let RevokeRequest { serial_hex, subject, reason } = dto.into_inner();
    let targets = resolve_targets(ledger, serial_hex, subject).await?;
    for s in targets {
        ledger.mark_revoked(s, reason.clone()).await.map_err(|e| { error!("Failed to record revocation: {}", e); Status::InternalServerError })?;
    }
    rebuild_crl_now(crl, ledger, ca).await?;
    Ok(Status::NoContent)
}

#[inline]
async fn resolve_targets(ledger: &State<Ledger>, serial_hex: Option<String>, subject: Option<String>) -> Result<Vec<String>, Status> {
    if let Some(s) = serial_hex { return if s.trim().is_empty() { Err(Status::BadRequest) } else { Ok(vec![s]) } };
    if let Some(subj) = subject {
        let entries = ledger.find_by_subject(&subj).await;
        return if entries.is_empty() { Err(Status::NotFound) } else { Ok(entries.into_iter().map(|e| e.serial_hex).collect()) };
    }
    Err(Status::BadRequest)
}

#[inline]
async fn rebuild_crl_now(crl: &State<CrlState>, ledger: &State<Ledger>, ca: &State<CaProvider>) -> Result<(), Status> {
    let (ca_cert, ca_key) = ca.get().await.map_err(|e| { error!("Failed to load CA for CRL rebuild: {}", e); Status::InternalServerError })?;
    let revs = ledger.revoked_as_revocations().await;
    crl.rebuild_crl_from(ca_cert.as_ref(), ca_key.as_ref(), revs).await.map_err(|e| { error!("Failed to rebuild CRL: {}", e); Status::InternalServerError })
}
