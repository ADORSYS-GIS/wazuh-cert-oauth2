#[get("/health")]
pub async fn health() -> &'static str {
    "OK"
}