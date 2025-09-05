use serde::Deserialize;

#[derive(Deserialize, Clone, Debug)]
pub struct Claims {
    pub sub: String,
    pub name: String,
    pub iss: String,
    pub exp: usize,
    // Add other claims as needed
}