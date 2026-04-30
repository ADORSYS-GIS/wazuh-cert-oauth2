use crate::state::{EnrollmentReport, ProxyState};
use rocket::State;
use rocket::serde::json::Json;
use wazuh_cert_oauth2_model::models::errors::AppResult;

#[get("/enrollment/report")]
#[tracing::instrument(skip(state))]
pub async fn get_enrollment_report(state: &State<ProxyState>) -> AppResult<Json<EnrollmentReport>> {
    let report = crate::state::generate_report(state).await?;
    Ok(Json(report))
}
