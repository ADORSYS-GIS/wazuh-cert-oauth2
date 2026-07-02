use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use wazuh_cert_oauth2_model::models::errors::AppResult;
use wazuh_cert_oauth2_model::services::http_client::HttpClient;

use super::{ProxyState, WazuhApiClient, oauth, utils};

impl ProxyState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server_base_url: String,
        spool_dir: PathBuf,
        http: HttpClient,
        retry_attempts: u32,
        retry_base: Duration,
        retry_max: Duration,
        spool_interval: Duration,
        static_bearer: Option<String>,
        oauth_issuer: Option<String>,
        oauth_client_id: Option<String>,
        oauth_client_secret: Option<String>,
        oauth_scope: Option<String>,
        oauth_audience: Option<String>,
        keycloak_revoke_reason: String,
        webhook_basic_user: Option<String>,
        webhook_basic_password: Option<String>,
        webhook_api_key: Option<String>,
        webhook_bearer_token: Option<String>,
        github_token: Option<String>,
        github_repo_owner: Option<String>,
        github_repo_name: Option<String>,
        keycloak_admin_base_url: Option<String>,
        wazuh_manager_url: Option<String>,
        wazuh_api_user: Option<String>,
        wazuh_api_password: Option<String>,
        wazuh_api_token: Option<String>,
        wazuh_eviction_grace_seconds: u64,
    ) -> AppResult<Self> {
        utils::ensure_spool_dir(&spool_dir);
        let oauth = oauth::build_oauth(
            oauth_issuer,
            oauth_client_id,
            oauth_client_secret,
            oauth_scope,
            oauth_audience,
        );
        let wazuh_api = wazuh_manager_url.map(|url| {
            WazuhApiClient::new(
                url,
                wazuh_api_user,
                wazuh_api_password,
                wazuh_api_token,
                wazuh_eviction_grace_seconds,
            )
        });
        Ok(Self {
            server_base_url,
            spool_dir,
            http,
            retry_attempts,
            retry_base,
            retry_max,
            spool_interval,
            static_bearer,
            oauth,
            revoke_reason: keycloak_revoke_reason,
            webhook_basic_user,
            webhook_basic_password,
            webhook_api_key,
            webhook_bearer_token,
            github_token,
            github_repo_owner,
            github_repo_name,
            keycloak_admin_base_url,
            token_cache: Arc::new(RwLock::new(None)),
            wazuh_api,
        })
    }
}
