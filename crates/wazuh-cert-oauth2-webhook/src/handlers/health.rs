use rocket::serde::json::Json;

use crate::models::Health;

#[get("/health")]
pub async fn health() -> Json<Health> {
    Json(Health::ok())
}
