use std::time::{SystemTime, UNIX_EPOCH};

pub mod claims;
pub mod document;
pub mod errors;
pub mod ledger_entry;
pub mod revoke_request;
pub mod sign_csr_request;
pub mod signed_cert_response;
pub mod user_representation;

/// Current Unix timestamp in seconds.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
