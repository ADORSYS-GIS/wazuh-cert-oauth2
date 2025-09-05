use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};
use log::{debug, error, info, warn};
use oauth2::basic::BasicClient;
use oauth2::{AuthType, AuthUrl, ClientId, ClientSecret, Scope, TokenResponse, TokenUrl};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tokio::time::sleep;
use wazuh_cert_oauth2_model::models::document::DiscoveryDocument;
use wazuh_cert_oauth2_model::models::revoke_request::RevokeRequest;
use wazuh_cert_oauth2_model::services::http_client::HttpClient;

#[derive(Clone)]
pub struct ProxyState {
    server_base_url: String,
    spool_dir: PathBuf,
    http: HttpClient,
    retry_attempts: u32,
    retry_base: Duration,
    retry_max: Duration,
    spool_interval: Duration,

    // Auth options
    static_bearer: Option<String>,
    oauth: Option<OAuthConfig>,

    // Keycloak mapping
    allowed_event_types: Vec<String>,
    revoke_reason: String,

    // Incoming webhook auth
    webhook_basic_user: Option<String>,
    webhook_basic_password: Option<String>,
    webhook_api_key: Option<String>,
    webhook_bearer_token: Option<String>,

    // Cached OAuth2 token
    token_cache: Arc<RwLock<Option<CachedToken>>>,
}

#[derive(Clone)]
struct OAuthConfig {
    issuer: String,
    client_id: String,
    client_secret: String,
    scope: Option<String>,
    audience: Option<String>,
}

#[derive(Clone)]
struct CachedToken {
    token: String,
    exp: Instant,
}

#[derive(Serialize, Deserialize)]
struct SpoolItem {
    req: RevokeRequest,
}

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
        keycloak_revoke_event_types: String,
        keycloak_revoke_reason: String,
        webhook_basic_user: Option<String>,
        webhook_basic_password: Option<String>,
        webhook_api_key: Option<String>,
        webhook_bearer_token: Option<String>,
    ) -> Result<Self> {
        // Ensure spool dir exists (best-effort)
        if !spool_dir.exists() {
            if let Err(e) = fs::create_dir_all(&spool_dir) {
                warn!("failed to create spool dir: {}", e);
            }
        }

        let oauth = match (oauth_issuer, oauth_client_id, oauth_client_secret) {
            (Some(iss), Some(id), Some(sec)) => Some(OAuthConfig {
                issuer: iss,
                client_id: id,
                client_secret: sec,
                scope: oauth_scope,
                audience: oauth_audience,
            }),
            _ => None,
        };

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
            allowed_event_types: keycloak_revoke_event_types
                .split(',')
                .filter_map(|s| {
                    let t = s.trim();
                    if t.is_empty() {
                        None
                    } else {
                        Some(t.to_ascii_lowercase())
                    }
                })
                .collect(),
            revoke_reason: keycloak_revoke_reason,
            webhook_basic_user,
            webhook_basic_password,
            webhook_api_key,
            webhook_bearer_token,
            token_cache: Arc::new(RwLock::new(None)),
        })
    }

    pub async fn forward_revoke_with_retry(&self, req: RevokeRequest) -> Result<()> {
        let url = format!("{}/api/revoke", self.server_base_url.trim_end_matches('/'));
        let mut attempt: u32 = 0;
        let max = self.retry_attempts.max(1);
        let mut delay = self.retry_base;

        loop {
            attempt += 1;
            match self.try_send(&url, &req).await {
                Ok(()) => {
                    info!("forwarded revoke after {} attempt(s)", attempt);
                    return Ok(());
                }
                Err(e) => {
                    warn!("send attempt {} failed: {}", attempt, e);
                    if attempt >= max {
                        return Err(e);
                    }
                    sleep(delay).await;
                    // Exponential backoff with cap
                    delay = std::cmp::min(self.retry_max, delay.saturating_mul(2));
                }
            }
        }
    }

    async fn try_send(&self, url: &str, req: &RevokeRequest) -> Result<()> {
        // Acquire token if needed
        let token = self.acquire_token().await?;

        let builder = self.http.client().post(url).json(req);

        let builder = if let Some(t) = token {
            builder.bearer_auth(t)
        } else {
            builder
        };

        let resp = builder.send().await?;
        if resp.status().as_u16() == 401 {
            // Unauthorized: clear token cache so next attempt refreshes
            let mut guard = self.token_cache.write().await;
            *guard = None;
        }
        if !resp.status().is_success() {
            return Err(anyhow!("upstream status {}", resp.status()));
        }
        Ok(())
    }

    async fn acquire_token(&self) -> Result<Option<String>> {
        if let Some(s) = &self.static_bearer {
            return Ok(Some(s.clone()));
        }
        if let Some(cfg) = &self.oauth {
            // Discover token endpoint and fetch token via oauth2 crate (client_credentials)
            let disc_url = format!(
                "{}/.well-known/openid-configuration",
                cfg.issuer.trim_end_matches('/')
            );
            let doc: DiscoveryDocument = self.http.fetch_json(&disc_url).await?;

            // Check cache first
            if let Some(cached) = self.token_cache.read().await.clone() {
                if Instant::now() < cached.exp {
                    return Ok(Some(cached.token));
                }
            }

            let mut basic_client = BasicClient::new(ClientId::new(cfg.client_id.clone()))
                .set_auth_uri(AuthUrl::new(doc.authorization_endpoint)?)
                .set_token_uri_option(Some(TokenUrl::new(doc.token_endpoint)?));

            basic_client =
                basic_client.set_client_secret(ClientSecret::new(cfg.client_secret.clone()));
            let client = basic_client.set_auth_type(AuthType::BasicAuth);

            let mut req = client.exchange_client_credentials()?;
            if let Some(s) = &cfg.scope {
                req = req.add_scope(Scope::new(s.clone()));
            }
            if let Some(aud) = &cfg.audience {
                req = req.add_extra_param("audience", aud.clone());
            }

            let token = req.request_async(self.http.client()).await?;
            let access = token.access_token().secret().to_string();
            // Cache with small skew (30s) to avoid using near-expiry tokens
            let now = Instant::now();
            let ttl = token
                .expires_in()
                .unwrap_or_else(|| Duration::from_secs(300));
            let skew = Duration::from_secs(30);
            let exp = now + ttl.saturating_sub(skew);
            let mut guard = self.token_cache.write().await;
            *guard = Some(CachedToken {
                token: access.clone(),
                exp,
            });
            return Ok(Some(access));
        }
        Ok(None)
    }

    pub fn is_allowed_event(&self, event_type_lower: &str, resource_path: Option<&str>) -> bool {
        if !self.allowed_event_types.is_empty() {
            return self
                .allowed_event_types
                .iter()
                .any(|e| e == event_type_lower);
        }
        // Fallback heuristic: act on user delete/disable events
        let t = event_type_lower;
        if t.contains("delete") || t.contains("disabled") {
            if let Some(rp) = resource_path {
                return rp.contains("users/");
            }
            return true;
        }
        false
    }

    pub fn revoke_reason(&self) -> Option<String> {
        Some(self.revoke_reason.clone())
    }

    // Incoming webhook auth helpers
    pub fn webhook_allows_anonymous(&self) -> bool {
        self.webhook_basic_user.is_none()
            && self.webhook_basic_password.is_none()
            && self.webhook_api_key.is_none()
            && self.webhook_bearer_token.is_none()
    }
    pub fn webhook_basic_user(&self) -> Option<&str> {
        self.webhook_basic_user.as_deref()
    }
    pub fn webhook_basic_password(&self) -> Option<&str> {
        self.webhook_basic_password.as_deref()
    }
    pub fn webhook_api_key(&self) -> Option<&str> {
        self.webhook_api_key.as_deref()
    }
    pub fn webhook_bearer_token(&self) -> Option<&str> {
        self.webhook_bearer_token.as_deref()
    }

    pub async fn queue_revoke(&self, req: RevokeRequest) -> Result<()> {
        let item = SpoolItem { req };
        let data = serde_json::to_vec(&item)?;
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let mut buf = [0u8; 8];
        rand::thread_rng().fill(&mut buf);
        let mut rid = String::with_capacity(buf.len() * 2);
        for b in buf {
            rid.push_str(&format!("{:02x}", b));
        }
        let filename = format!("revoke-{}-{}.json", ms, rid);
        let path = self.spool_dir.join(&filename);
        let tmp = self.spool_dir.join(format!("{}.tmp", filename));
        tokio::fs::write(&tmp, data).await?;
        tokio::fs::rename(&tmp, &path).await?;
        Ok(())
    }
}

pub async fn spawn_spool_processor(state: ProxyState) -> Result<()> {
    info!(
        "spool processor running; dir={} interval={:?}",
        state.spool_dir.display(),
        state.spool_interval
    );
    loop {
        if let Err(e) = process_once(&state).await {
            error!("error in spool cycle: {}", e);
        }
        sleep(state.spool_interval).await;
    }
}

async fn process_once(state: &ProxyState) -> Result<()> {
    let mut dir = match tokio::fs::read_dir(&state.spool_dir).await {
        Ok(d) => d,
        Err(e) => {
            warn!("spool read_dir failed: {}", e);
            return Ok(());
        }
    };

    while let Some(entry) = dir.next_entry().await? {
        let path = entry.path();
        if !is_json(&path) {
            continue;
        }
        match tokio::fs::read(&path).await {
            Ok(bytes) => match serde_json::from_slice::<SpoolItem>(&bytes) {
                Ok(item) => {
                    debug!("processing spool file: {}", path.display());
                    match state.forward_revoke_with_retry(item.req).await {
                        Ok(()) => {
                            debug!("forwarded; removing {}", path.display());
                            let _ = tokio::fs::remove_file(&path).await;
                        }
                        Err(e) => {
                            warn!("still failing for {}: {}", path.display(), e);
                        }
                    }
                }
                Err(e) => {
                    warn!("invalid spool item {}; deleting: {}", path.display(), e);
                    let _ = tokio::fs::remove_file(&path).await;
                }
            },
            Err(e) => warn!("failed to read {}: {}", path.display(), e),
        }
    }

    Ok(())
}

fn is_json(p: &Path) -> bool {
    p.extension().and_then(|s| s.to_str()).unwrap_or("") == "json"
}
