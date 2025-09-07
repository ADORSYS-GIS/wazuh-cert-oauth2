use rocket::State;
use rocket::http::{ContentType, Status};

use crate::handlers::middle::JwtToken;
use crate::models::ca_config::CaProvider;
use crate::shared::crl::CrlState;
use crate::shared::crl::RevocationEntry;
use crate::shared::ledger::Ledger;
use openssl::asn1::Asn1Time;
use openssl::x509::X509Crl;
use rocket::serde::json::Json;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info};

#[get("/crl/issuing.crl")]
pub async fn get_crl(
    crl: &State<CrlState>,
    ledger: &State<Ledger>,
    ca: &State<CaProvider>,
) -> Result<(ContentType, Vec<u8>), Status> {
    info!("GET /crl/issuing.crl requested");

    // Try read existing CRL
    let mut bytes = crl.read_crl_file().await.unwrap_or_else(|_| Vec::new());

    // If missing or expired, rebuild via mpsc and re-read
    if bytes.is_empty() || is_crl_expired(&bytes) {
        info!("CRL missing or expired; triggering on-demand rebuild");
        let (ca_cert, ca_key) = ca.get().await.map_err(|e| {
            error!("Failed to load CA for CRL rebuild: {}", e);
            Status::InternalServerError
        })?;
        let revs = ledger.revoked_as_revocations().await;
        crl.request_rebuild(ca_cert, ca_key, revs)
            .await
            .map_err(|e| {
                error!("Failed to rebuild CRL: {}", e);
                Status::InternalServerError
            })?;
        // Re-read after successful rebuild
        bytes = crl.read_crl_file().await.map_err(|e| {
            error!("Failed to read CRL file after rebuild: {}", e);
            Status::NotFound
        })?;
    }

    debug!("CRL bytes length: {}", bytes.len());
    Ok((ContentType::new("application", "pkix-crl"), bytes))
}

/// Fetch the current revocation DB as JSON (admin/auth token recommended)
#[get("/revocations")]
pub async fn get_revocations(
    _token: JwtToken,
    ledger: &State<Ledger>,
) -> Json<Vec<RevocationEntry>> {
    info!("GET /api/revocations requested");
    let revs = ledger.revoked_as_revocations().await;
    debug!("revocations count: {}", revs.len());
    Json(revs)
}

fn is_crl_expired(bytes: &[u8]) -> bool {
    // If parse fails, be conservative and treat as expired
    let crl = match X509Crl::from_der(bytes) {
        Ok(c) => c,
        Err(_) => return true,
    };
    let next = match crl.next_update() {
        Some(n) => n,
        None => return true,
    };
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    // If conversion fails, assume expired to force rebuild
    let now_asn1 = match Asn1Time::from_unix(now_unix) {
        Ok(t) => t,
        Err(_) => return true,
    };
    // Consider expired if nextUpdate <= now
    // Use ordering if available; fall back to not-expired on panic
    next <= now_asn1.as_ref()
}
