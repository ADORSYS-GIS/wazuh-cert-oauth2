use std::sync::Arc;
use std::time::Duration;
use tracing::error;
use wazuh_cert_oauth2_model::models::errors::{AppError, AppResult};
use wazuh_cert_oauth2_model::services::http_client::HttpClient;

use crate::adapters::auth::default::DefaultWebhookAuthProvider;
use crate::adapters::auth::google::GoogleWebhookAuthProvider;
use crate::adapters::idp::ferriskey::FerriskeyAdapter;
use crate::adapters::idp::google::GoogleIdpAdapter;
use crate::adapters::idp::keycloak::KeycloakAdapter;
use crate::handlers::enrollment::get_enrollment_report;
use crate::handlers::evict::internal_evict;
use crate::handlers::health::health;
use crate::handlers::webhook::send_webhook;
use crate::opts::{IdpType, Opt, WebhookAuthType};
use crate::ports::idp::IdpProvider;
use crate::ports::webhook_auth::WebhookAuthProvider;
use crate::state::{ProxyState, spawn_spool_processor};

pub fn build_idp(opt: &Opt, http_client: HttpClient) -> Arc<dyn IdpProvider> {
    match opt.idp_type {
        IdpType::Keycloak => Arc::new(KeycloakAdapter::from_opt(opt, http_client)),
        IdpType::Ferriskey => Arc::new(FerriskeyAdapter::from_opt(
            opt.idp_admin_base_url.clone(),
            opt.idp_revoke_reason.clone(),
            http_client,
        )),
        IdpType::Google => Arc::new(GoogleIdpAdapter {
            admin_base_url: opt
                .idp_admin_base_url
                .clone()
                .unwrap_or_else(|| "https://admin.googleapis.com/admin/directory/v1".to_string()),
            customer: opt.google_customer.clone(),
            domain: opt.google_domain.clone(),
            revoke_reason: opt
                .idp_revoke_reason
                .clone()
                .unwrap_or_else(|| "Google Workspace event".to_string()),
            http: http_client,
        }),
    }
}

pub fn build_webhook_auth(opt: &Opt) -> Arc<dyn WebhookAuthProvider> {
    let default = Arc::new(DefaultWebhookAuthProvider::from_opt(opt));
    match opt.webhook_auth_type {
        WebhookAuthType::Default => default,
        WebhookAuthType::Google => Arc::new(GoogleWebhookAuthProvider {
            channel_id: opt.google_channel_id.clone().unwrap_or_default(),
            channel_token: opt.google_channel_token.clone().unwrap_or_default(),
            fallback: default,
        }),
    }
}

pub fn build_state(opt: &Opt) -> AppResult<ProxyState> {
    opt.validate().map_err(AppError::Configuration)?;
    let http_client = HttpClient::new_with_defaults()?;
    let idp = build_idp(opt, http_client.clone());
    let webhook_auth = build_webhook_auth(opt);
    let state = ProxyState::new(
        opt.server_base_url.clone(),
        opt.spool_dir.clone(),
        http_client,
        opt.retry_attempts,
        Duration::from_millis(opt.retry_base_ms),
        Duration::from_millis(opt.retry_max_ms),
        Duration::from_secs(opt.spool_interval_secs),
        opt.proxy_bearer_token.clone(),
        opt.oauth_issuer.clone(),
        opt.oauth_client_id.clone(),
        opt.oauth_client_secret.clone(),
        opt.oauth_scope.clone(),
        opt.oauth_audience.clone(),
        idp,
        webhook_auth,
        opt.github_token.clone(),
        opt.github_repo_owner.clone(),
        opt.github_repo_name.clone(),
        opt.wazuh_manager_url.clone(),
        opt.wazuh_api_user.clone(),
        opt.wazuh_api_password.clone(),
        opt.wazuh_api_token.clone(),
        opt.wazuh_ar_command_unix.clone(),
        opt.wazuh_ar_command_windows.clone(),
        opt.wazuh_eviction_grace_seconds,
        opt.wazuh_ar_spool_ttl_seconds,
    )?;
    Ok(state)
}

pub fn spawn_spool_bg(state: ProxyState) {
    let bg = state.clone();
    tokio::spawn(async move {
        if let Err(e) = spawn_spool_processor(bg).await {
            error!("spool processor exited: {}", e);
        }
    });
}

pub async fn launch_rocket(state: ProxyState) -> AppResult<()> {
    rocket::build()
        .manage(state)
        .mount("/", routes![health])
        .mount(
            "/api",
            routes![send_webhook, get_enrollment_report, internal_evict],
        )
        .launch()
        .await
        .map_err(|e| AppError::RocketError(Box::new(e)))?;
    Ok(())
}
