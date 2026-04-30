use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use wazuh_cert_oauth2_model::models::errors::AppResult;
use wazuh_cert_oauth2_model::models::ledger_entry::LedgerEntry;

use super::ProxyState;
use super::oauth::acquire_oauth_token;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeycloakUser {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentReport {
    pub enabled_users: usize,
    pub active_certs: usize,
    pub gap_count: usize,
    pub missing_users: Vec<String>,
    pub generated_at_unix: u64,
}

pub async fn generate_report(state: &ProxyState) -> AppResult<EnrollmentReport> {
    debug!("Generating enrollment report");

    // 1. Fetch Users from Keycloak
    let token = acquire_oauth_token(state).await?.ok_or_else(|| {
        wazuh_cert_oauth2_model::models::errors::AppError::UpstreamError(
            "OAuth2 not configured, cannot audit users".to_string(),
        )
    })?;

    let admin_url = state.keycloak_admin_base_url.as_ref().ok_or_else(|| {
        wazuh_cert_oauth2_model::models::errors::AppError::UpstreamError(
            "KEYCLOAK_ADMIN_BASE_URL not configured. This is required for enrollment auditing."
                .to_string(),
        )
    })?;

    // Use a large max as a stopgap for non-trivial deployments.
    // Real fix would involve cursor/offset pagination.
    let users_url = format!("{}/users?max=5000", admin_url.trim_end_matches('/'));

    debug!("Fetching users from Keycloak: {}", users_url);
    let users: Vec<KeycloakUser> = state.http.fetch_json_auth(&users_url, &token).await?;

    // 2. Fetch Active Certs from Server
    let server_url = format!(
        "{}/api/ledger/active",
        state.server_base_url.trim_end_matches('/')
    );
    debug!("Fetching active certs from server: {}", server_url);
    let certs: Vec<LedgerEntry> = state.http.fetch_json_auth(&server_url, &token).await?;

    // 3. Correlate
    // Note: This assumes the certificate subject field stores the Keycloak user UUID (u.id).
    let enrolled_subs: std::collections::HashSet<String> =
        certs.into_iter().map(|c| c.subject).collect();

    if enrolled_subs.is_empty() && !users.is_empty() {
        debug!(
            "Correlation set is empty despite having users; verify that certificate subjects match Keycloak IDs"
        );
    }

    let mut missing = Vec::new();
    let mut enrolled_count = 0;

    for u in users.into_iter().filter(|u| u.enabled) {
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
            .map_err(|_| {
                wazuh_cert_oauth2_model::models::errors::AppError::UpstreamError(
                    "System clock is before Unix epoch".to_string(),
                )
            })?
            .as_secs(),
    };

    info!(
        "Enrollment audit complete: {} enabled users, {} active certs, {} gap",
        report.enabled_users, report.active_certs, report.gap_count
    );

    Ok(report)
}
