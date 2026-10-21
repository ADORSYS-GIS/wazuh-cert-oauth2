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

#[cfg(test)]
mod tests {
    use super::generate_report;
    use crate::state::{ProxyState, SpoolBackend};
    use std::path::PathBuf;
    use std::time::Duration;
    use wazuh_cert_oauth2_model::services::http_client::HttpClient;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn build_state(server: &MockServer, kc: &MockServer) -> ProxyState {
        ProxyState::new(
            format!("{}/server", server.uri()),
            SpoolBackend::Dir {
                dir: std::env::temp_dir().join(format!("audit-spool-{}", std::process::id())),
                dead_letter_dir: PathBuf::from("/tmp/wazuh-webhook-dead-letter-audit"),
            },
            HttpClient::new_with_defaults().expect("http client"),
            2,
            Duration::from_millis(5),
            Duration::from_millis(20),
            Duration::from_secs(1),
            Duration::from_secs(86400),
            None,
            Some(format!("{}/realms/main", kc.uri())),
            Some("client".to_string()),
            Some("secret".to_string()),
            None,
            None,
            "revoke".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(kc.uri()),
            None,
            None,
            None,
            None,
            30,
            false,
            None,
        )
        .expect("state should build")
    }

    #[tokio::test]
    async fn generate_report_correlates_users_and_certs() {
        let server = MockServer::start().await;
        let kc = MockServer::start().await;

        // OAuth discovery + token exchange against the issuer.
        Mock::given(method("GET"))
            .and(path("/realms/main/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": format!("{}/realms/main", kc.uri()),
                "authorization_endpoint": format!("{}/realms/main/auth", kc.uri()),
                "token_endpoint": format!("{}/realms/main/token", kc.uri()),
                "jwks_uri": format!("{}/realms/main/jwks", kc.uri())
            })))
            .mount(&kc)
            .await;
        Mock::given(method("POST"))
            .and(path("/realms/main/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "audit-token",
                "token_type": "Bearer",
                "expires_in": 300
            })))
            .mount(&kc)
            .await;

        // Keycloak users endpoint.
        Mock::given(method("GET"))
            .and(path("/users"))
            .and(query_param("max", "5000"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": "u1", "username": "alice", "enabled": true},
                {"id": "u2", "username": "bob", "enabled": true},
                {"id": "u3", "username": "carol", "enabled": false}
            ])))
            .mount(&kc)
            .await;

        // Server active certs endpoint.
        Mock::given(method("GET"))
            .and(path("/server/api/ledger/active"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"subject": "u1", "serial_hex": "AA", "issued_at_unix": 1, "revoked": false}
            ])))
            .mount(&server)
            .await;

        let state = build_state(&server, &kc);
        let report = generate_report(&state)
            .await
            .expect("report should generate");

        // u1 enrolled, u2 missing, u3 disabled (not counted).
        assert_eq!(report.enabled_users, 2);
        assert_eq!(report.active_certs, 1);
        assert_eq!(report.gap_count, 1);
        assert_eq!(report.missing_users, vec!["bob".to_string()]);
    }
}
