use rocket::serde::json::Json;
use log::info;

use crate::models::Health;

#[get("/health")]
pub async fn health() -> Json<Health> {
    debug!("GET /health requested");
    Json(Health::ok())
}
