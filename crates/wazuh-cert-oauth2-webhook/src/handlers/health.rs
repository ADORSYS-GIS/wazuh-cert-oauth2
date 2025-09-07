use rocket::serde::json::Json;

use crate::models::Health;
use tracing::debug;

#[get("/health")]
pub async fn health() -> Json<Health> {
    debug!("GET /health requested");
    Json(Health::ok())
}
