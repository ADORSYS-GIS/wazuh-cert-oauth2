use rocket::serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct RegisterAgentDto {
    pub name: String,
}

#[derive(Serialize)]
pub struct UserKey {
    pub public_key: String,
    pub private_key: String,
}