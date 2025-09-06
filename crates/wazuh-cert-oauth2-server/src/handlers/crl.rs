use rocket::State;
use rocket::http::{ContentType, Status};

use crate::handlers::middle::JwtToken;
use crate::shared::crl::CrlState;
use crate::shared::crl::RevocationEntry;
use crate::shared::ledger::Ledger;
use rocket::serde::json::Json;
use tracing::{debug, error, info};

#[get("/crl/issuing.crl")]
pub async fn get_crl(crl: &State<CrlState>) -> anyhow::Result<(ContentType, Vec<u8>), Status> {
    info!("GET /crl/issuing.crl requested");
    let bytes = crl.read_crl_file().await.map_err(|e| {
        error!("Failed to read CRL file: {}", e);
        Status::NotFound
    })?;
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
