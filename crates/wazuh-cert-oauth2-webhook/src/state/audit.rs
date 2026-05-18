use tracing::{debug, info};
use wazuh_cert_oauth2_model::models::errors::{AppError, AppResult};
use wazuh_cert_oauth2_model::models::ledger_entry::LedgerEntry;

use super::ProxyState;
use super::oauth::acquire_oauth_token;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EnrollmentReport {
    pub enabled_users: usize,
    pub active_certs: usize,
    pub gap_count: usize,
    pub missing_users: Vec<String>,
    pub generated_at_unix: u64,
}

pub async fn generate_report(state: &ProxyState) -> AppResult<EnrollmentReport> {
    debug!("Generating enrollment report");

    // 1. Acquire token
    let token = acquire_oauth_token(state).await?.ok_or_else(|| {
        AppError::UpstreamError("OAuth2 not configured, cannot audit users".to_string())
    })?;

    // 2. Fetch users via IdP adapter
    let idp_users = state.idp.fetch_users(&token).await?;

    // 3. Fetch active certs from the server
    let server_url = format!(
        "{}/api/ledger/active",
        state.server_base_url.trim_end_matches('/')
    );
    debug!("Fetching active certs from server: {}", server_url);
    let certs: Vec<LedgerEntry> = state.http.fetch_json_auth(&server_url, &token).await?;

    // 4. Correlate
    let enrolled_subs: std::collections::HashSet<String> =
        certs.into_iter().map(|c| c.subject).collect();

    if enrolled_subs.is_empty() && !idp_users.is_empty() {
        debug!(
            "Correlation set is empty despite having users; verify that certificate subjects match IdP user IDs"
        );
    }

    let mut missing = Vec::new();
    let mut enrolled_count = 0;

    for u in idp_users.into_iter().filter(|u| u.enabled) {
        if enrolled_subs.contains(&u.id) {
            enrolled_count += 1;
        } else {
            missing.push(u.username);
        }
    }

    let report = EnrollmentReport {
        enabled_users: enrolled_count + missing.len(),
        active_certs: enrolled_count,
        gap_count: missing.len(),
        missing_users: missing,
        generated_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| AppError::UpstreamError("System clock is before Unix epoch".to_string()))?
            .as_secs(),
    };

    info!(
        "Enrollment audit complete: {} enabled users, {} active certs, {} gap",
        report.enabled_users, report.active_certs, report.gap_count
    );

    Ok(report)
}
