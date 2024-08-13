use rocket::serde::Deserialize;

#[derive(Deserialize)]
pub struct Claims {
    sub: String,
    exp: usize,
    iat: usize,
    jti: String,
    iss: String,
    aud: String,
    typ: String,
    azp: String,
    // Add other claims as needed
}
