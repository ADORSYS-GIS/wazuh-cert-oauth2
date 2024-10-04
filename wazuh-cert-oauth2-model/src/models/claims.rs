use serde::Deserialize;

#[derive(Deserialize, Clone, Debug)]
pub struct Claims {
    pub sub: String,
    pub name: String,
    pub exp: usize,
    pub iat: usize,
    pub jti: String,
    pub iss: String,
    pub aud: String,
    pub typ: String,
    pub azp: String,
    // Add other claims as needed
}