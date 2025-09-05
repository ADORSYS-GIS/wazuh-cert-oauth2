use rocket::http::{ContentType, Status};
use rocket::State;

use crate::shared::crl::CrlState;
use crate::shared::crl::RevocationEntry;
use crate::shared::ledger::Ledger;
use crate::handlers::middle::JwtToken;
use rocket::serde::json::Json;
use log::error;

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
pub async fn get_revocations(_token: JwtToken, ledger: &State<Ledger>) -> Json<Vec<RevocationEntry>> {
    Json(ledger.revoked_as_revocations().await)
}
