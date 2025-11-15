use std::time::Duration;
use tracing::error;
use wazuh_cert_oauth2_model::models::errors::{AppError, AppResult};
use wazuh_cert_oauth2_model::services::http_client::HttpClient;

use crate::handlers::health::health;
use crate::handlers::webhook::send_webhook;
use crate::opts::Opt;
use crate::state::{ProxyState, spawn_spool_processor};

pub fn build_state(opt: &Opt) -> AppResult<ProxyState> {
    let http_client = HttpClient::new_with_defaults()?;
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
        opt.keycloak_revoke_reason.clone(),
        opt.webhook_basic_user.clone(),
        opt.webhook_basic_password.clone(),
        opt.webhook_api_key.clone(),
        opt.webhook_bearer_token.clone(),
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
        .mount("/api", routes![send_webhook])
        .launch()
        .await
        .map_err(|e| AppError::RocketError(Box::new(e)))?;
    Ok(())
}
