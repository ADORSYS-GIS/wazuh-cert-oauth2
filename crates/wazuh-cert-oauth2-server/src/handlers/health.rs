use crate::models::health::Health;
use rocket::serde::json::Json;
use tracing::debug;

#[get("/health")]
pub async fn health() -> Json<Health> {
    debug!("GET /health requested");
    Json(Health::new())
}
