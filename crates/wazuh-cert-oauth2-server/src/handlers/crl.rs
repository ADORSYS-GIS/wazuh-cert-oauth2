use rocket::State;
use rocket::http::{ContentType, Status};

use crate::handlers::middle::JwtToken;
use crate::shared::crl::CrlState;
use crate::shared::crl::RevocationEntry;
use crate::shared::ledger::Ledger;
use log::error;
use rocket::serde::json::Json;

#[get("/crl/issuing.crl")]
pub async fn get_crl(crl: &State<CrlState>) -> Result<(ContentType, Vec<u8>), Status> {
    let bytes = crl.read_crl_file().await.map_err(|e| {
        error!("Failed to read CRL file: {}", e);
        Status::NotFound
    })?;
    Ok((ContentType::new("application", "pkix-crl"), bytes))
}

/// Fetch the current revocation DB as JSON (admin/auth token recommended)
#[get("/api/revocations")]
pub async fn get_revocations(
    _token: JwtToken,
    ledger: &State<Ledger>,
) -> Json<Vec<RevocationEntry>> {
    Json(ledger.revoked_as_revocations().await)
}
