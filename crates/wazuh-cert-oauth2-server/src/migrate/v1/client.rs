use std::time::Instant;

use crate::migrate::v1::opts::KeycloakAuthMethod;
use reqwest::Client;
use serde::Deserialize;
use tracing::{info, warn};
use wazuh_cert_oauth2_model::models::errors::{AppError, AppResult};
use wazuh_cert_oauth2_model::models::user_representation::SimpleUserRepresentation;

use crate::migrate::v1::opts::MigrateOpt;

#[derive(Deserialize)]
struct KcTokenResponse {
    access_token: String,
}

pub struct KeycloakSession {
    client: Client,
    opt: MigrateOpt,
    token: Option<String>,
    last_attempt: Instant,
}

impl KeycloakSession {
    pub fn new(client: Client, opt: MigrateOpt) -> Self {
        Self {
            client,
            opt,
            // Seed far enough in the past so the very first call always fires.
            token: None,
            last_attempt: Instant::now()
                .checked_sub(std::time::Duration::from_secs(600))
                .unwrap_or(Instant::now()),
        }
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn opt(&self) -> &MigrateOpt {
        &self.opt
    }

    /// Return a valid Keycloak access token, refreshing if the cached token
    /// is stale or missing and enough time has passed since the last attempt.
    ///
    /// Uses a hard-coded 200s refresh threshold on top of Keycloak's default
    /// 300s access-token lifespan, giving a 100s margin for clock skew and
    /// request latency.  If the realm is configured with a shorter lifespan
    /// the token may expire before the next refresh — in that case a 401
    /// response from a subsequent API call will cause the entry to fall
    /// through to `unmatched_no_match`.
    pub async fn get_token(&mut self) -> AppResult<Option<String>> {
        let refresh_threshold = std::time::Duration::from_secs(200);
        let needs_refresh = self.last_attempt.elapsed() > refresh_threshold;

        if needs_refresh {
            self.last_attempt = Instant::now();
            match keycloak_get_token(&self.client, &self.opt).await {
                Ok(Some(t)) => {
                    self.token = Some(t.clone());
                    Ok(Some(t))
                }
                Ok(None) => {
                    self.token = None;
                    Ok(None)
                }
                Err(e) => {
                    self.token = None;
                    Err(e)
                }
            }
        } else {
            Ok(self.token.clone())
        }
    }
}

async fn keycloak_get_token(client: &Client, opt: &MigrateOpt) -> AppResult<Option<String>> {
    let base = if opt.keycloak_admin_url.trim_end_matches('/').is_empty() {
        return Err(AppError::ValidationError(
            "KEYCLOAK_ADMIN_URL is required for Keycloak matching".into(),
        ));
    } else {
        opt.keycloak_admin_url.trim_end_matches('/').to_string()
    };

    let (url, params) = match opt.keycloak_auth_method {
        KeycloakAuthMethod::ClientCredentials => {
            let client_id = opt.keycloak_client_id.as_deref().ok_or_else(|| {
                AppError::ValidationError(
                    "KEYCLOAK_CLIENT_ID required for client_credentials".into(),
                )
            })?;
            let client_secret = opt.keycloak_client_secret.as_deref().ok_or_else(|| {
                AppError::ValidationError(
                    "KEYCLOAK_CLIENT_SECRET required for client_credentials".into(),
                )
            })?;
            (
                format!(
                    "{}/realms/{}/protocol/openid-connect/token",
                    base, opt.keycloak_realm
                ),
                vec![
                    ("grant_type", "client_credentials"),
                    ("client_id", client_id),
                    ("client_secret", client_secret),
                ],
            )
        }
        KeycloakAuthMethod::Password => {
            let user = opt.keycloak_admin_user.as_deref().ok_or_else(|| {
                AppError::ValidationError("KEYCLOAK_ADMIN_USER required for password auth".into())
            })?;
            let password = opt.keycloak_admin_password.as_deref().ok_or_else(|| {
                AppError::ValidationError(
                    "KEYCLOAK_ADMIN_PASSWORD required for password auth".into(),
                )
            })?;
            (
                format!("{}/realms/master/protocol/openid-connect/token", base),
                vec![
                    ("grant_type", "password"),
                    ("client_id", "admin-cli"),
                    ("username", user),
                    ("password", password),
                ],
            )
        }
    };

    let resp = client
        .post(&url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(&params)
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            let body: KcTokenResponse = r.json().await.map_err(|e| {
                AppError::UpstreamError(format!("Keycloak token parse failed: {}", e))
            })?;
            Ok(Some(body.access_token))
        }
        Ok(r) => {
            warn!(
                "Keycloak auth failed with status {} — matching unavailable",
                r.status()
            );
            Ok(None)
        }
        Err(e) => {
            warn!("Keycloak auth request failed: {} — matching unavailable", e);
            Ok(None)
        }
    }
}

pub async fn keycloak_lookup_user(
    client: &Client,
    opt: &MigrateOpt,
    token: &str,
    uuid: &str,
) -> Option<String> {
    let base = if opt.keycloak_admin_url.trim_end_matches('/').is_empty() {
        return None;
    } else {
        opt.keycloak_admin_url.trim_end_matches('/').to_string()
    };
    let url = format!(
        "{}/admin/realms/{}/users/{}",
        base, opt.keycloak_realm, uuid
    );

    let resp = client.get(&url).bearer_auth(token).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }

    let user: SimpleUserRepresentation = resp.json().await.ok()?;

    // Reconstruct the display name from Keycloak's Admin API profile.
    //
    // At enrollment time the client uses `Claims::get_name()` which prefers
    // the JWT `name` claim and falls back to `preferred_username`.  The
    // default Keycloak mapper for the `name` claim is `${firstName}
    // ${lastName}`, so reconstructing from profile fields is correct for
    // the common case.  However, if the `name` claim was set by a custom
    // mapper, or if enrollment fell back to `preferred_username`, the
    // reconstructed name won't match and the entry will be unresolved.
    let display_name = match (user.first_name.as_deref(), user.last_name.as_deref()) {
        (Some(f), Some(l)) => format!("{} {}", f, l),
        (Some(f), None) => f.to_string(),
        (None, Some(l)) => l.to_string(),
        (None, None) => user.username?,
    };

    if display_name.is_empty() {
        None
    } else {
        info!(
            uuid = %uuid,
            display_name = %display_name,
            "Reconstructed display name from Keycloak profile for agent-name matching"
        );
        Some(display_name)
    }
}

#[cfg(test)]
mod tests {
    use super::{KeycloakSession, keycloak_get_token, keycloak_lookup_user};
    use crate::migrate::v1::opts::{KeycloakAuthMethod, MigrateOpt};
    use reqwest::Client;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn opt(base_url: &str) -> MigrateOpt {
        MigrateOpt {
            input: "/data/ledger.csv".to_string(),
            output: "ledger-migrated.csv".to_string(),
            unresolved: "unresolved.csv".to_string(),
            report: "migration-report.txt".to_string(),
            wazuh_manager_url: "https://wazuh".to_string(),
            wazuh_api_user: "user".to_string(),
            wazuh_api_password: "pass".to_string(),
            wazuh_tls_verify: true,
            wazuh_ca_bundle: None,
            keycloak_admin_url: base_url.to_string(),
            keycloak_realm: "main".to_string(),
            keycloak_auth_method: KeycloakAuthMethod::Password,
            keycloak_admin_user: Some("admin".to_string()),
            keycloak_admin_password: Some("secret".to_string()),
            keycloak_client_id: None,
            keycloak_client_secret: None,
            keycloak_tls_verify: true,
            keycloak_ca_bundle: None,
        }
    }

    fn token_mock() -> Mock {
        Mock::given(method("POST"))
            .and(path("/realms/master/protocol/openid-connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "kc-token"
            })))
    }

    #[tokio::test]
    async fn keycloak_get_token_with_password_auth() {
        let server = MockServer::start().await;
        token_mock().mount(&server).await;

        let client = Client::new();
        let token = keycloak_get_token(&client, &opt(&server.uri()))
            .await
            .expect("token should be fetched");
        assert_eq!(token.as_deref(), Some("kc-token"));
    }

    #[tokio::test]
    async fn keycloak_get_token_with_client_credentials() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/realms/main/protocol/openid-connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "cc-token"
            })))
            .mount(&server)
            .await;

        let mut o = opt(&server.uri());
        o.keycloak_auth_method = KeycloakAuthMethod::ClientCredentials;
        o.keycloak_client_id = Some("cid".to_string());
        o.keycloak_client_secret = Some("csecret".to_string());

        let client = Client::new();
        let token = keycloak_get_token(&client, &o)
            .await
            .expect("token should be fetched");
        assert_eq!(token.as_deref(), Some("cc-token"));
    }

    #[tokio::test]
    async fn keycloak_get_token_errors_when_admin_url_empty() {
        let mut o = opt("https://kc");
        o.keycloak_admin_url = "".to_string();
        let client = Client::new();
        assert!(keycloak_get_token(&client, &o).await.is_err());
    }

    #[tokio::test]
    async fn keycloak_get_token_errors_when_password_creds_missing() {
        let mut o = opt("https://kc");
        o.keycloak_admin_user = None;
        let client = Client::new();
        assert!(keycloak_get_token(&client, &o).await.is_err());
    }

    #[tokio::test]
    async fn keycloak_get_token_returns_none_on_auth_failure() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/realms/master/protocol/openid-connect/token"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let client = Client::new();
        let token = keycloak_get_token(&client, &opt(&server.uri()))
            .await
            .expect("should not error");
        assert!(token.is_none());
    }

    #[tokio::test]
    async fn keycloak_lookup_user_reconstructs_display_name() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/admin/realms/main/users/uuid-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "uuid-1",
                "username": "alice",
                "firstName": "Alice",
                "lastName": "Smith",
                "enabled": true
            })))
            .mount(&server)
            .await;

        let client = Client::new();
        let name = keycloak_lookup_user(&client, &opt(&server.uri()), "token", "uuid-1").await;
        assert_eq!(name.as_deref(), Some("Alice Smith"));
    }

    #[tokio::test]
    async fn keycloak_lookup_user_falls_back_to_username() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/admin/realms/main/users/uuid-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "uuid-2",
                "username": "bob",
                "enabled": true
            })))
            .mount(&server)
            .await;

        let client = Client::new();
        let name = keycloak_lookup_user(&client, &opt(&server.uri()), "token", "uuid-2").await;
        assert_eq!(name.as_deref(), Some("bob"));
    }

    #[tokio::test]
    async fn keycloak_lookup_user_returns_none_on_non_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/admin/realms/main/users/uuid-3"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let client = Client::new();
        let name = keycloak_lookup_user(&client, &opt(&server.uri()), "token", "uuid-3").await;
        assert!(name.is_none());
    }

    #[tokio::test]
    async fn keycloak_session_caches_token_within_refresh_window() {
        let server = MockServer::start().await;
        token_mock().mount(&server).await;

        let client = Client::new();
        let mut session = KeycloakSession::new(client, opt(&server.uri()));
        let first = session.get_token().await.expect("first token");
        assert_eq!(first.as_deref(), Some("kc-token"));
        // Second call within the refresh window should reuse the cached token
        // without another HTTP request.
        let second = session.get_token().await.expect("cached token");
        assert_eq!(second.as_deref(), Some("kc-token"));
    }
}
