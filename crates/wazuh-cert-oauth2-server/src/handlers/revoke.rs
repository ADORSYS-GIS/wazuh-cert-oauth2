use rocket::State;
use rocket::http::Status;
use rocket::serde::json::Json;

use wazuh_cert_oauth2_metrics::record_http_params;
use wazuh_cert_oauth2_model::models::revoke_request::RevokeRequest;

use crate::handlers::middle::JwtToken;
use crate::models::ca_config::CaProvider;
use crate::shared::crl::CrlState;
use crate::shared::ledger::Ledger;
use tracing::{debug, error, info};

/// Revoke a certificate by serial and optional reason, then rebuild CRL
#[post("/revoke", format = "application/json", data = "<dto>")]
#[tracing::instrument(skip(_token, dto, crl, ledger, ca))]
pub async fn revoke(
    _token: JwtToken,
    dto: Json<RevokeRequest>,
    crl: &State<CrlState>,
    ledger: &State<Ledger>,
    ca: &State<CaProvider>,
) -> Result<Status, Status> {
    info!("POST /revoke called");
    let RevokeRequest {
        serial_hex,
        subject,
        reason,
    } = dto.into_inner();
    record_http_params(
        "/api/revoke",
        "POST",
        subject.as_ref().map(|s| !s.is_empty()).unwrap_or(false),
        serial_hex.as_ref().map(|s| !s.is_empty()).unwrap_or(false),
    );
    debug!(
        "revoke request params: serial_hex_present={} subject_present={} reason={:?}",
        serial_hex.as_ref().map(|s| !s.is_empty()).unwrap_or(false),
        subject.as_ref().map(|s| !s.is_empty()).unwrap_or(false),
        reason
    );
    let targets = resolve_targets(ledger, serial_hex, subject).await?;
    info!(
        "revocation targets resolved: {} certificates",
        targets.len()
    );
    for s in targets {
        ledger.mark_revoked(s, reason.clone()).await.map_err(|e| {
            error!("Failed to record revocation: {}", e);
            Status::InternalServerError
        })?;
    }
    rebuild_crl_now(crl, ledger, ca).await?;
    info!("revocation recorded and CRL rebuild triggered");
    Ok(Status::NoContent)
}

#[tracing::instrument(skip(ledger))]
async fn resolve_targets(
    ledger: &State<Ledger>,
    serial_hex: Option<String>,
    subject: Option<String>,
) -> Result<Vec<String>, Status> {
    debug!("resolving revocation targets");
    if let Some(s) = serial_hex {
        return if s.trim().is_empty() {
            Err(Status::BadRequest)
        } else {
            Ok(vec![s])
        };
    };
    if let Some(subj) = subject {
        let entries = ledger.find_by_subject(&subj).await;
        info!("found {} entries for subject", entries.len());
        return if entries.is_empty() {
            Err(Status::NoContent)
        } else {
            Ok(entries.into_iter().map(|e| e.serial_hex).collect())
        };
    }
    Err(Status::BadRequest)
}

#[tracing::instrument(skip(crl, ledger, ca))]
async fn rebuild_crl_now(
    crl: &State<CrlState>,
    ledger: &State<Ledger>,
    ca: &State<CaProvider>,
) -> Result<(), Status> {
    let (ca_cert, ca_key) = ca.get().await.map_err(|e| {
        error!("Failed to load CA for CRL rebuild: {}", e);
        Status::InternalServerError
    })?;
    let revs = ledger.revoked_as_revocations().await;
    info!("rebuilding CRL with {} revocations", revs.len());
    crl.request_rebuild(ca_cert, ca_key, revs)
        .await
        .map_err(|e| {
            error!("Failed to rebuild CRL: {}", e);
            Status::InternalServerError
        })
}
