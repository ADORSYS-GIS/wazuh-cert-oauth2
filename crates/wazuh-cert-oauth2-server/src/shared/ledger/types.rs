use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub subject: String,
    pub serial_hex: String,
    pub issued_at_unix: u64,
    pub revoked: bool,
    pub revoked_at_unix: Option<u64>,
    pub reason: Option<String>,
    pub issuer: Option<String>,
    pub realm: Option<String>,
}
