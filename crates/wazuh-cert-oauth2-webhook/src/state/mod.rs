use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use wazuh_cert_oauth2_model::services::http_client::HttpClient;

use crate::ports::idp::IdpProvider;
use crate::ports::webhook_auth::WebhookAuthProvider;

pub(crate) mod audit;
mod builder;
pub(crate) mod core;
mod oauth;
pub mod spool;
mod utils;
pub(crate) mod wazuh_api;

pub use audit::{EnrollmentReport, generate_report};
pub use spool::spawn_spool_processor;
pub use wazuh_api::WazuhApiClient;

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

    /// Pluggable Identity Provider adapter.
    pub(crate) idp: Arc<dyn IdpProvider>,

    /// Pluggable inbound webhook authentication adapter.
    pub(crate) webhook_auth: Arc<dyn WebhookAuthProvider>,

    pub(crate) github_token: Option<String>,
    pub(crate) github_repo_owner: Option<String>,
    pub(crate) github_repo_name: Option<String>,

    pub(crate) token_cache: Arc<RwLock<Option<oauth::CachedToken>>>,

    /// Wazuh manager API client; `None` when eviction is not configured.
    pub(crate) wazuh_api: Option<WazuhApiClient>,
}

impl ProxyState {}
