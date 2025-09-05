use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use wazuh_cert_oauth2_model::services::http_client::HttpClient;

use super::{oauth, utils, ProxyState};

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
    ) -> Result<Self> {
        utils::ensure_spool_dir(&spool_dir);
        let oauth = oauth::build_oauth(
            oauth_issuer,
            oauth_client_id,
            oauth_client_secret,
            oauth_scope,
            oauth_audience,
        );
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
            token_cache: Arc::new(RwLock::new(None)),
        })
    }
}

