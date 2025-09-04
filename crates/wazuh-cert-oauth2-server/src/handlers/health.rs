use rocket::serde::json::Json;
use crate::models::health::Health;

#[get("/health")]
pub async fn health() -> Json<Health> {
    Json(Health::new())
}