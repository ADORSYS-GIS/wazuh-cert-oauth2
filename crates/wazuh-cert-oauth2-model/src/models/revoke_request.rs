use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct RevokeRequest {
    pub serial_hex: Option<String>,
    pub subject: Option<String>,
    pub reason: Option<String>,
}
