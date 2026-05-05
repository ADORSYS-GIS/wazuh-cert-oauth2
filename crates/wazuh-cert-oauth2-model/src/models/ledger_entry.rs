use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub subject: String,
    pub serial_hex: String,
    pub issued_at_unix: u64,
    pub revoked: bool,
    #[serde(default)]
    pub revoked_at_unix: Option<u64>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub realm: Option<String>,
    #[serde(default)]
    pub wazuh_agent_name: Option<String>,
}
