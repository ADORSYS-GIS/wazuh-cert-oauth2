use crate::handlers::middle::JwtToken;
use crate::shared::ledger::Ledger;
use crate::shared::ledger::LedgerEntry;
use rocket::State;
use rocket::serde::json::Json;

/// All certificates (active and revoked)
#[get("/ledger")]
#[tracing::instrument(skip(token, ledger), fields(sub = %token.claims.sub))]
pub async fn get_all_ledger(token: JwtToken, ledger: &State<Ledger>) -> Json<Vec<LedgerEntry>> {
    Json(ledger.find_all().await)
}

/// Active (non-revoked) certificates only
#[get("/ledger/active")]
#[tracing::instrument(skip(token, ledger), fields(sub = %token.claims.sub))]
pub async fn get_active_ledger(token: JwtToken, ledger: &State<Ledger>) -> Json<Vec<LedgerEntry>> {
    Json(ledger.find_active().await)
}

/// Revoked certificates only
#[get("/ledger/revoked")]
#[tracing::instrument(skip(token, ledger), fields(sub = %token.claims.sub))]
pub async fn get_revoked_ledger(token: JwtToken, ledger: &State<Ledger>) -> Json<Vec<LedgerEntry>> {
    Json(ledger.find_revoked().await)
}
