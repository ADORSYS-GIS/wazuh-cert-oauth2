use serde::Deserialize;

#[derive(Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
    pub jti: String,
    pub iss: String,
    pub aud: String,
    pub typ: String,
    pub azp: String,
    // Add other claims as needed
}
