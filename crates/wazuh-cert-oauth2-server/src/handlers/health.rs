use crate::models::health::Health;
use rocket::serde::json::Json;
use log::info;

#[get("/health")]
pub async fn health() -> Json<Health> {
    debug!("GET /health requested");
    Json(Health::new())
}
