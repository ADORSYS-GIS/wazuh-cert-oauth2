use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use wazuh_cert_oauth2_model::services::http_client::HttpClient;

mod builder;
pub(crate) mod core;
mod oauth;
mod spool;
mod utils;

pub use spool::spawn_spool_processor;

#[derive(Clone)]
pub struct ProxyState {
    pub(crate) server_base_url: String,
    pub(crate) spool_dir: PathBuf,
    pub(crate) http: HttpClient,
    pub(crate) retry_attempts: u32,
    pub(crate) retry_base: Duration,
    pub(crate) retry_max: Duration,
    pub(crate) spool_interval: Duration,

    pub(crate) static_bearer: Option<String>,
    pub(crate) oauth: Option<oauth::OAuthConfig>,

    revoke_reason: String,

    webhook_basic_user: Option<String>,
    webhook_basic_password: Option<String>,
    webhook_api_key: Option<String>,
    webhook_bearer_token: Option<String>,

    pub(crate) token_cache: Arc<RwLock<Option<oauth::CachedToken>>>,
}

impl ProxyState {}
