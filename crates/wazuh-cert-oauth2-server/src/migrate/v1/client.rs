use reqwest::Client;
use serde::Deserialize;
use tracing::{info, warn};
use wazuh_cert_oauth2_model::models::errors::{AppError, AppResult};

use crate::migrate::v1::opts::MigrateOpt;

#[derive(Deserialize)]
struct KcTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct KcUserResponse {
    #[serde(default)]
    first_name: Option<String>,
    #[serde(default)]
    last_name: Option<String>,
    #[serde(default)]
    username: Option<String>,
}

pub async fn keycloak_get_token(client: &Client, opt: &MigrateOpt) -> AppResult<Option<String>> {
    let base = opt.keycloak_admin_url.trim_end_matches('/').to_string();

    let (url, params) = match opt.keycloak_auth_method.as_str() {
        "client_credentials" => {
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
        _ => {
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
    let base = opt.keycloak_admin_url.trim_end_matches('/').to_string();
    let url = format!(
        "{}/admin/realms/{}/users/{}",
        base, opt.keycloak_realm, uuid
    );

    let resp = client.get(&url).bearer_auth(token).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }

    let user: KcUserResponse = resp.json().await.ok()?;

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
