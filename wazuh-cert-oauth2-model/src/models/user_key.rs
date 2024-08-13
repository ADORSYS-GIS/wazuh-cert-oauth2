use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct UserKey {
    pub public_key: String,
    pub private_key: String,
}