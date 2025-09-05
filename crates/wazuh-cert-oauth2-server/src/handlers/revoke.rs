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
    let RevokeRequest {
        serial_hex,
        subject,
        reason,
    } = dto.into_inner();

    // Resolve target serials
    let mut targets: Vec<String> = Vec::new();
    if let Some(s) = serial_hex {
        if s.trim().is_empty() {
            return Err(Status::BadRequest);
        }
        targets.push(s);
    } else if let Some(subj) = subject {
        let entries = ledger.find_by_subject(&subj).await;
        if entries.is_empty() {
            return Err(Status::NotFound);
        }
        targets.extend(entries.into_iter().map(|e| e.serial_hex));
    } else {
        return Err(Status::BadRequest);
    }

    for s in targets {
        ledger.mark_revoked(s, reason.clone()).await.map_err(|e| {
            error!("Failed to record revocation: {}", e);
            Status::InternalServerError
        })?;
    }

    // Rebuild CRL immediately using local CA
    let (ca_cert, ca_key) = ca.get().await.map_err(|e| {
        error!("Failed to load CA for CRL rebuild: {}", e);
        Status::InternalServerError
    })?;
    let revs = ledger.revoked_as_revocations().await;
    crl.rebuild_crl_from(ca_cert.as_ref(), ca_key.as_ref(), revs)
        .await
        .map_err(|e| {
            error!("Failed to rebuild CRL: {}", e);
            Status::InternalServerError
        })?;

    Ok(Status::NoContent)
}
