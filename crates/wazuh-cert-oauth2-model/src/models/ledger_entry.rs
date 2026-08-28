use serde::{Deserialize, Serialize};

/// Default certificate validity period in days, used for `not_after_unix`
/// computation when recording issued certificates.
pub const CERTIFICATE_VALIDITY_DAYS: u64 = 365;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub subject: String,
    pub serial_hex: String,
    pub issued_at_unix: u64,
    pub not_after_unix: u64,
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

impl LedgerEntry {
    /// Returns `true` if the certificate has expired (i.e. `not_after_unix` is
    /// non-zero and in the past). A zero `not_after_unix` (legacy entries
    /// without expiry data) is treated as *not* expired to avoid breaking
    /// existing deployments.
    pub fn is_expired(&self) -> bool {
        self.not_after_unix > 0 && crate::models::now_unix() >= self.not_after_unix
    }
}
