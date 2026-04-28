use crate::handlers::middle::JwtToken;
use crate::shared::ledger::Ledger;
use crate::shared::ledger::LedgerEntry;
use rocket::State;
use rocket::serde::json::Json;

/// Get all active (non-revoked) certificates from the ledger
#[get("/ledger/active")]
#[tracing::instrument(skip(token, ledger), fields(sub = %token.claims.sub))]
pub async fn get_active_ledger(token: JwtToken, ledger: &State<Ledger>) -> Json<Vec<LedgerEntry>> {
    Json(ledger.find_active().await)
}
